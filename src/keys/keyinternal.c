/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "keyinternal.h"
#include <noise/protocol/util.h>
#include <string.h>

static char const base64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * \brief Closes a stream and cleans up sensitive material.
 *
 * \param stream The stream to close.
 */
void noise_key_stream_close(NoiseKeyStream *stream)
{
    if (stream->file)
        fclose(stream->file);
    if (stream->dh)
        noise_dhstate_free(stream->dh);
    if (stream->sign)
        noise_signstate_free(stream->sign);
    noise_clean(stream, sizeof(NoiseKeyStream));
}

/**
 * \brief Reads a single character from an input stream.
 *
 * \param stream The stream to read from.
 *
 * \return The character, or -1 at EOF.
 */
int noise_key_stream_getc(NoiseKeyStream *stream)
{
    const NoiseBuffer *buffer = stream->buffer;
    if (stream->saw_eof)
        return -1;
    if (buffer) {
        if (stream->posn >= buffer->size) {
            stream->saw_eof = 1;
            return -1;
        } else {
            return buffer->data[(stream->posn)++];
        }
    } else {
        int ch = getc(stream->file);
        if (ch < 0)
            stream->saw_eof = 1;
        return ch;
    }
}

/**
 * \brief Ungets a single character back into an input stream.
 *
 * \param stream The stream to read from.
 * \param ch The last character that was read, to be put back in.
 */
void noise_key_stream_ungetc(NoiseKeyStream *stream, int ch)
{
    const NoiseBuffer *buffer = stream->buffer;
    if (stream->saw_eof)
        return;
    if (buffer) {
        if (stream->posn > 0)
            --(stream->posn);
    } else {
        ungetc(ch, stream->file);
    }
}

/**
 * \brief Expects the end of the input to occur.
 *
 * \param stream The stream to read from.
 *
 * \return Returns non-zero if at EOF, or zero if there are more characters.
 */
int noise_key_stream_expect_eof(NoiseKeyStream *stream)
{
    int ch = noise_key_stream_getc(stream);
    if (ch < 0)
        return 1;
    noise_key_stream_ungetc(stream, ch);
    return 0;
}

/**
 * \brief Expects the end of the input to occur after optional whitespace.
 *
 * \param stream The stream to read from.
 *
 * \return Returns non-zero if at EOF, or zero if there are non-whitespace
 * characters in the stream.
 */
int noise_key_stream_expect_white_eof(NoiseKeyStream *stream)
{
    int ch;
    for (;;) {
        ch = noise_key_stream_getc(stream);
        if (ch < 0)
            break;
        if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            noise_key_stream_ungetc(stream, ch);
            return 0;
        }
    }
    return 1;
}

/**
 * \brief Reads binary data directly from an input stream.
 *
 * \param stream The stream to read from.
 * \param data The buffer to read the binary data into.
 * \param max_len The maximum length of \a data in bytes.
 *
 * \return The number of bytes that were written to \a data.
 */
size_t noise_key_stream_read_binary
    (NoiseKeyStream *stream, uint8_t *data, size_t max_len)
{
    int ch;
    size_t posn = 0;
    while (posn < max_len) {
        ch = noise_key_stream_getc(stream);
        if (ch < 0)
            break;
        data[posn++] = (uint8_t)ch;
    }
    return posn;
}

/**
 * \brief Reads base64-encoded binary data directly from an input stream.
 *
 * \param stream The stream to read from.
 * \param data The buffer to read the binary data into.
 * \param max_len The maximum length of \a data in bytes.
 * \param multi_line Non-zero if multi-line base64 is allowed, zero if the
 * base64 data must appear on a single line.
 *
 * \return The number of bytes that were written to \a data.
 *
 * This function stops at the first character which is not base64
 * or when \a max_len is reached.  Partial base64 sequences will be
 * parsed as though they were followed by enough '=' characters to make
 * up a full 4-character sequence.
 */
size_t noise_key_stream_read_base64
    (NoiseKeyStream *stream, uint8_t *data, size_t max_len, int multi_line)
{
    // TODO
    return 0;
}

/**
 * \brief Writes binary data to an output stream.
 *
 * \param stream The stream to write to.
 * \param data Points to the data to write.
 * \param len The number of bytes to write.
 *
 * \return Non-zero on success, zero on error.
 */
int noise_key_stream_write_binary
    (NoiseKeyStream *stream, const uint8_t *data, size_t len)
{
    if (stream->file) {
        if (fwrite(data, 1, len, stream->file) == len)
            return 1;
        stream->saw_eof = 1;
        return 0;
    } else {
        NoiseBuffer *buffer = stream->buffer;
        size_t available = buffer->max_size - buffer->size;
        if (available < len) {
            stream->saw_eof = 1;
            return 0;
        }
        memcpy(buffer->data + buffer->size, data, len);
        buffer->size += len;
        return 1;
    }
}

/**
 * \brief Writes base64-encoded data to an output stream.
 *
 * \param stream The stream to write to.
 * \param data Points to the data to write.
 * \param len The number of bytes to write.
 * \param multi_line Non-zero if the base64 data can be formatted over
 * multiple lines, zero for a single line only.
 *
 * \return Non-zero on success, zero on error.
 */
int noise_key_stream_write_base64
    (NoiseKeyStream *stream, const uint8_t *data, size_t len, int multi_line)
{
    // TODO
    return 0;
}
