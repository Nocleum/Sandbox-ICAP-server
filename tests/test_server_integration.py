from __future__ import annotations

from .helpers import (
    decode_chunks,
    encrypt_container,
    make_request,
    parse_icap_response,
    transact,
)


def _parse_http(
    payload: bytes,
    headers: dict[bytes, bytes],
) -> tuple[bytes, bytes]:
    assert b"res-hdr=0, res-body=" in headers[b"encapsulated"]
    offset = int(headers[b"encapsulated"].split(b"res-body=", 1)[1])
    http_headers = payload[:offset]
    body = decode_chunks(payload[offset:])
    return http_headers, body


def test_unencrypted_body_is_returned_unchanged(running_server) -> None:
    body = b"\x00\xff\x80plain\r\ndata"
    request = make_request(body, chunk_sizes=[1, 2, 3, 1, 4])
    response = transact(running_server, request)

    status, headers, payload, _ = parse_icap_response(response)
    assert status == b"ICAP/1.0 200 OK"
    assert b"istag" in headers
    assert headers[b"istag"] == b'"sandboxqav1"'

    http_headers, actual_body = _parse_http(payload, headers)
    assert actual_body == body
    expected_length = b"Content-Length: " + str(len(body)).encode()
    assert expected_length + b"\r\n" in http_headers
    assert b"X-Keep: exact-value\r\n" in http_headers
    assert http_headers.startswith(b"HTTP/1.1 200 OK\r\n")


def test_decrypts_container_split_across_arbitrary_chunks(
    running_server,
) -> None:
    plaintext = b"\x00binary\xffpayload\r\nwith arbitrary bytes"
    encrypted_body = encrypt_container(plaintext)
    # Границы частей пересекают маркер ENC1, nonce, ciphertext и tag.
    sizes = [1, 1, 1, 1, 2, 3, 4, 1, 7, 2, 5, 1, 3, 1, 2]
    request = make_request(encrypted_body, chunk_sizes=sizes)
    response = transact(running_server, request)

    status, headers, payload, _ = parse_icap_response(response)
    assert status == b"ICAP/1.0 200 OK"

    http_headers, actual_body = _parse_http(payload, headers)
    assert actual_body == plaintext
    expected_length = b"Content-Length: " + str(len(plaintext)).encode()
    assert expected_length + b"\r\n" in http_headers
    assert b"Content-Type: application/octet-stream\r\n" in http_headers
    assert b"X-Keep: exact-value\r\n" in http_headers


def test_empty_plaintext_is_valid(running_server) -> None:
    encrypted_body = encrypt_container(b"")
    chunk_sizes = [4, 12, 1, 1, 1, 1, 12]
    request = make_request(encrypted_body, chunk_sizes=chunk_sizes)
    response = transact(running_server, request)

    status, headers, payload, _ = parse_icap_response(response)
    assert status == b"ICAP/1.0 200 OK"

    http_headers, actual_body = _parse_http(payload, headers)
    assert actual_body == b""
    assert b"Content-Length: 0\r\n" in http_headers


def test_short_enc1_container_returns_4xx_with_istag(running_server) -> None:
    response = transact(running_server, make_request(b"ENC1too-short"))
    status, headers, payload, _ = parse_icap_response(response)

    assert status.startswith(b"ICAP/1.0 4")
    assert b"istag" in headers
    assert headers[b"encapsulated"] == b"null-body=0"
    assert payload == b""


def test_authentication_failure_returns_4xx(running_server) -> None:
    encrypted_body = bytearray(encrypt_container(b"secret"))
    encrypted_body[-1] ^= 0x80
    response = transact(running_server, make_request(bytes(encrypted_body)))

    status, headers, _, _ = parse_icap_response(response)
    assert status.startswith(b"ICAP/1.0 4")
    assert b"istag" in headers


def test_content_length_mismatch_returns_4xx(running_server) -> None:
    body = b"abc"
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 9\r\n\r\n"
    )
    request = make_request(body, http_headers=headers)
    response = transact(running_server, request)

    status, _, _, _ = parse_icap_response(response)
    assert status.startswith(b"ICAP/1.0 4")


def test_large_response_is_chunked_and_binary_safe(running_server) -> None:
    body = bytes(range(256)) * 100
    response = transact(
        running_server,
        make_request(body, chunk_sizes=[len(body)]),
    )

    status, headers, payload, _ = parse_icap_response(response)
    assert status == b"ICAP/1.0 200 OK"
    _, actual_body = _parse_http(payload, headers)
    assert actual_body == body


def test_request_can_arrive_in_small_tcp_writes(running_server) -> None:
    body = encrypt_container(b"fragmented TCP write")
    request = make_request(body, chunk_sizes=[1] * len(body))
    fragments = [request[i:i + 3] for i in range(0, len(request), 3)]
    response = transact(running_server, request, fragments=fragments)

    status, headers, payload, _ = parse_icap_response(response)
    assert status == b"ICAP/1.0 200 OK"
    _, actual_body = _parse_http(payload, headers)
    assert actual_body == b"fragmented TCP write"


def test_server_continues_after_bad_container(running_server) -> None:
    bad_response = transact(running_server, make_request(b"ENC1bad"))
    assert parse_icap_response(bad_response)[0].startswith(b"ICAP/1.0 4")

    good_body = b"server still works"
    good_request = make_request(encrypt_container(good_body))
    good_response = transact(running_server, good_request)
    status, headers, payload, _ = parse_icap_response(good_response)
    assert status == b"ICAP/1.0 200 OK"
    _, actual_body = _parse_http(payload, headers)
    assert actual_body == good_body


def test_wrong_service_path_returns_404(running_server) -> None:
    request = make_request(b"abc", uri="icap://127.0.0.1/other")
    response = transact(running_server, request)
    status, headers, _, _ = parse_icap_response(response)

    assert status == b"ICAP/1.0 404 Not Found"
    assert b"istag" in headers


def test_non_respmod_method_returns_405(running_server) -> None:
    request = make_request(b"abc", method="REQMOD")
    response = transact(running_server, request)
    status, _, _, _ = parse_icap_response(response)

    assert status == b"ICAP/1.0 405 Method Not Allowed"


def test_malformed_icap_chunk_size_returns_4xx(running_server) -> None:
    request = make_request(b"abc")
    malformed_request = request.replace(
        b"3\r\nabc\r\n",
        b"G\r\nabc\r\n",
        1,
    )
    response = transact(running_server, malformed_request)
    status, headers, payload, _ = parse_icap_response(response)

    assert status.startswith(b"ICAP/1.0 4")
    assert b"istag" in headers
    assert payload == b""
