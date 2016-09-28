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

#include <noise/protobufs.h>
#include <string.h>
#include <stdlib.h>

/**
 * \file protobufs.h
 * \brief Protobufs support interface
 */

/**
 * \file protobufs.c
 * \brief Protobufs support implementation
 */

/**
 * \defgroup protobufs Protobufs Support API
 *
 * This API provides a minimalistic implementation of the
 * <a href="https://developers.google.com/protocol-buffers/">Protocol
 * Buffers</a> mechanism for serializing structured data.  It is primarily
 * targeted at handling certificates and other serializable data in the
 * Noise-C library and other security-sensitive domains.  It can be used by
 * applications also, although applications are free to use another
 * full-featured protobufs implementation if they wish.
 *
 * Except for the "prepare" and "finish" functions, this API is not typically
 * used directly by the programmer.  Instead the <tt>noise-protoc</tt>
 * compiler is used to compile a <tt>.proto</tt> file into custom C code.
 * The custom C code then calls this library to perform low-level reading
 * and writing tasks.
 *
 * \section protobuf_compiling Compiling a protobuf description
 *
 * The <tt>noise-protoc</tt> program can be used to compile a protobuf
 * description into C code.  There are some limitations in this program
 * compared with the standard protobuf tools:
 *
 * \li Only "proto3" syntax is supported.  There is no support for "proto2".
 * \li The "oneof", "service", and "map" keywords are not supported.
 * \li The "import" and "reserved" keywords are recognized but ignored.
 * \li The generated code is designed for reading and writing in-memory
 * buffers, typically restricted to the Noise packet limit of 65535 bytes.
 * \li File and stream based operations for arbitrary-length message
 * structures are not supported.
 *
 * These limitations may be addressed in future versions.
 *
 * TODO
 *
 * \section protobuf_writing Writing to a protobuf
 *
 * Writing a protobuf-enabled structure starts by preparing the buffer
 * to receive the data:
 *
 * \code
 * uint8_t data[MAX_DATA_SIZE];
 * NoiseProtobuf pbuf;
 * noise_protobuf_prepare_output(&pbuf, data, sizeof(data));
 * \endcode
 *
 * Fields and other structures can then be written to the protobuf.
 * Consider the following standard protobuf example:
 *
 * \code
 * message Person {
 *     required string name = 1;
 *     required int32 id = 2;
 *     optional string email = 3;
 * }
 * \endcode
 *
 * This message may be serialized as follows:
 *
 * \code
 * size_t end;
 * noise_protobuf_write_end_element(&pbuf, &end);
 * if (email)
 *     noise_protobuf_write_string(&pbuf, EMAIL_TAG, email, strlen(email));
 * noise_protobuf_write_int32(&pbuf, ID_TAG, id);
 * noise_protobuf_write_string(&pbuf, NAME_TAG, name, strlen(name));
 * noise_protobuf_write_start_element(&pbuf, 0, end);
 * \endcode
 *
 * As can be seen, fields are written in <i>reverse order</i>, from the last
 * to the first.  This ordering makes the support code more efficient
 * because it doesn't have to constantly rearrange the buffer's contents
 * to deal with variable-length structures.  However, it does mean that
 * once an entire message has been serialized, it ends up being packed
 * into the end of the original buffer.
 *
 * Once all message details have been written, the buffer is "finished"
 * to recover the region containing the serialized message data:
 *
 * \code
 * uint8_t *msg;
 * size_t size;
 * int err = noise_protobuf_finish_output(&pbuf, &msg, &size);
 * \endcode
 *
 * If an error occurred during the writing process (for example, running
 * out of buffer space), then it is reported at the end.  It is safe to
 * keep writing to a buffer that has experienced a previous error.
 * Any further write requests will be ignored.
 *
 * If the application needs the data to be aligned at the start of
 * the output buffer, it can use noise_protobuf_finish_output_shift()
 * instead to shift the data down.
 *
 * Sometimes the application needs to know how big a structure is before
 * writing it to allocate an appropriately-sized buffer.  Structures can
 * be "measured" by writing them to a dummy protobuf that has been prepared
 * for measurement instead:
 *
 * \code
 * NoiseProtobuf pbuf;
 * size_t end, size;
 * noise_protobuf_prepare_measure(&pbuf, MAX_SIZE);
 * noise_protobuf_write_end_element(&pbuf, &end);
 * if (email)
 *     noise_protobuf_write_string(&pbuf, EMAIL_TAG, email, strlen(email));
 * noise_protobuf_write_int32(&pbuf, ID_TAG, id);
 * noise_protobuf_write_string(&pbuf, NAME_TAG, name, strlen(name));
 * noise_protobuf_write_start_element(&pbuf, 0, end);
 * noise_protobuf_finish_measure(&pbuf, &size);
 * \endcode
 *
 * The advantage of this approach is that the application can use the
 * same code to both measure and write a structure.  The difference is
 * only in how the protobuf is prepared and finished.
 *
 * \section protobuf_reading Reading from a protobuf
 *
 * Reading from a protobuf is similar to writing.  We start by calling
 * noise_protobuf_prepare_input() to specify the data to be parsed and
 * its size:
 *
 * \code
 * NoiseProtobuf pbuf;
 * noise_protobuf_prepare_input(&pbuf, data, size);
 * \endcode
 *
 * \code
 * size_t end;
 * noise_protobuf_read_start_element(&pbuf, 0, &end);
 * while (!noise_protobuf_read_at_end_element(&pbuf, end)) {
 *     switch (noise_protobuf_peek_tag(&pbuf)) {
 *     case NAME_TAG:
 *         noise_protobuf_read_string(&buf, NAME_TAG, name, sizeof(name), &name_size);
 *         break;
 *     case ID_TAG:
 *         noise_protobuf_read_int32(&buf, ID_TAG, &id);
 *         break;
 *     case EMAIL_TAG:
 *         noise_protobuf_read_string(&buf, EMAIL_TAG, email, sizeof(email), &email_size);
 *         break;
 *     default:
 *         noise_protobuf_read_skip(&pbuf);
 *         break;
 *     }
 * }
 * noise_protobuf_read_end_element(&pbuf, end);
 * \endcode
 *
 * Structures are read in <tt>forward order</tt> from the first field
 * to the last.  However, the protobuf format allows tagged fields within a
 * message to be ordered in any way so it is usually necessary to "switch"
 * on the tag type to determine what to do next.
 *
 * The noise_protobuf_read_skip() function skips fields that are not
 * understood.  The application calls this whenever it encounters an unknown
 * field.  Alternatively the application can call noise_protobuf_read_stop()
 * to abort the current parsing process with an "invalid format" error.
 *
 * Once the parsing process has finished, the application calls
 * noise_protobuf_finish_input() to determine if there were any errors:
 *
 * \code
 * int err = noise_protobuf_finish_input(&pbuf);
 * \endcode
 *
 * If the application has not consumed the entire buffer's contents,
 * then an "invalid format" error will occur at this point.
 */
/**@{*/

/**
 * \typedef NoiseProtobuf
 * \brief Information about a buffer being read from or written to by
 * the protobufs support API.
 */

/* Reference: https://developers.google.com/protocol-buffers/docs/encoding */

/** @cond */

/* Wire types */
#define NOISE_PROTOBUF_WIRE_VARINT      0
#define NOISE_PROTOBUF_WIRE_64BIT       1
#define NOISE_PROTOBUF_WIRE_DELIM       2
#define NOISE_PROTOBUF_WIRE_32BIT       5
#define NOISE_PROTOBUF_WIRE_MASK        7
#define NOISE_PROTOBUF_WIRE_BITS        3

/* Maximum supported tag value */
#define NOISE_PROTOBUF_MAX_TAG  ((((uint64_t)1) << 29) - 1)

/** @endcond */

/**
 * \brief Prepares a protobuf for reading input.
 *
 * \param pbuf The protobuf to be prepared.
 * \param data The data to be parsed.
 * \param size The size of the data to be parsed in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a data is NULL.
 *
 * \sa noise_protobuf_finish_input()
 */
int noise_protobuf_prepare_input
    (NoiseProtobuf *pbuf, const uint8_t *data, size_t size)
{
    if (!pbuf || !data)
        return NOISE_ERROR_INVALID_PARAM;
    pbuf->data = (uint8_t *)data;
    pbuf->size = size;
    pbuf->posn = 0;
    pbuf->error = NOISE_ERROR_NONE;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Prepares a protobuf for writing output.
 *
 * \param pbuf The protobuf to be prepared.
 * \param data The data buffer to write to.
 * \param size The maximum size of the storage at \a data in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a data is NULL.
 *
 * \sa noise_protobuf_finish_output()
 */
int noise_protobuf_prepare_output
    (NoiseProtobuf *pbuf, uint8_t *data, size_t size)
{
    if (!pbuf || !data)
        return NOISE_ERROR_INVALID_PARAM;
    pbuf->data = data;
    pbuf->size = size;
    pbuf->posn = size;
    pbuf->error = NOISE_ERROR_NONE;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Prepares a protobuf for measuring the size of a structure.
 *
 * \param pbuf The protobuf to be prepared.
 * \param max_size The maximum size of the serialized data.  An error will be
 * reported by noise_protobuf_finish_measure() if this size is insufficient
 * to contain the entire structure.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 *
 * \sa noise_protobuf_finish_measure()
 */
int noise_protobuf_prepare_measure(NoiseProtobuf *pbuf, size_t max_size)
{
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    pbuf->data = 0;
    pbuf->size = max_size;
    pbuf->posn = max_size;
    pbuf->error = NOISE_ERROR_NONE;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Finishes reading input from a protobuf.
 *
 * \param pbuf The protobuf.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the input data was incorrect
 * and could not be successfully parsed.
 * \return NOISE_ERROR_NO_MEMORY if there was insufficient memory to
 * allocate the fields and structures within the input.
 *
 * It is possible that some of the fields may have been parsed successfully
 * before the error occurred.  It is the responsibility of the application
 * to clean up any intermediate objects that were created during the
 * failed parsing process.
 *
 * \sa noise_protobuf_prepare_input()
 */
int noise_protobuf_finish_input(NoiseProtobuf *pbuf)
{
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (pbuf->posn != pbuf->size) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    return NOISE_ERROR_NONE;
}

/**
 * \brief Finishes writing output to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param data Receives a pointer to the actual data that was written
 * to \a pbuf.
 * \param size Receives the number of bytes of actual \a data that were written.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf, \a data, or \a size is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the available space in the buffer
 * was insufficient to serialize the entire structure.
 * \return NOISE_ERROR_INVALID_FORMAT if an attempt was made to write a
 * string to the protobuf that was not in UTF-8.
 *
 * The data will be aligned with the end of the original buffer.  If the
 * application needs data that is aligned with the start of the original
 * buffer, it should call noise_protobuf_finish_output_shift() instead.
 *
 * The entire buffer's contents should be considered invalid if an error
 * occurs.  It is possible that some of the fields may have been written
 * successfully before the error occurred, but there is no way to know
 * how many fields succeeded.
 *
 * \sa noise_protobuf_finish_output_shift(), noise_protobuf_prepare_output()
 */
int noise_protobuf_finish_output
    (NoiseProtobuf *pbuf, uint8_t **data, size_t *size)
{
    if (data)
        *data = 0;
    if (size)
        *size = 0;
    if (!pbuf || !data || !size)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (pbuf->data)
        *data = pbuf->data + pbuf->posn;
    *size = pbuf->size - pbuf->posn;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Finishes writing output to a protobuf and shifts it down.
 *
 * \param pbuf The protobuf.
 * \param data Receives a pointer to the actual data that was written
 * to \a pbuf.
 * \param size Receives the number of bytes of actual \a data that were written.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf, \a data, or \a size is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the available space in the buffer
 * was insufficient to serialize the entire structure.
 * \return NOISE_ERROR_INVALID_FORMAT if an attempt was made to write a
 * string to the protobuf that was not in UTF-8.
 *
 * This function differs from noise_protobuf_finish_output() in that
 * it will shift the data down to the start of the underlying buffer
 * before returning a pointer to the data.
 *
 * The entire buffer's contents should be considered invalid if an error
 * occurs.  It is possible that some of the fields may have been written
 * successfully before the error occurred, but there is no way to know
 * how many fields succeeded.
 *
 * \sa noise_protobuf_finish_output(), noise_protobuf_prepare_output()
 */
int noise_protobuf_finish_output_shift
    (NoiseProtobuf *pbuf, uint8_t **data, size_t *size)
{
    if (data)
        *data = 0;
    if (size)
        *size = 0;
    if (!pbuf || !data || !size)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (pbuf->data) {
        if (pbuf->posn != 0) {
            memmove(pbuf->data, pbuf->data + pbuf->posn,
                    pbuf->size - pbuf->posn);
        }
        *data = pbuf->data;
    }
    *size = pbuf->size - pbuf->posn;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Finishes measuring the size of data written to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param size Receives the number of bytes of memory that is needed to
 * represent the structure that was written.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a size is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the maximum space in the original
 * buffer is insufficient to contain the entire structure.
 * \return NOISE_ERROR_INVALID_FORMAT if an attempt was made to write a
 * string to the protobuf that was not in UTF-8.
 *
 * If an error occurred, then \a size will be set to zero.
 *
 * \sa noise_protobuf_prepare_measure()
 */
int noise_protobuf_finish_measure(NoiseProtobuf *pbuf, size_t *size)
{
    if (size)
        *size = 0;
    else
        return NOISE_ERROR_INVALID_PARAM;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    *size = pbuf->size - pbuf->posn;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reserves space in a protobuf.
 *
 * \param pbuf The protobuf.
 * \param size The number of bytes to reserve.
 * \param data Returns a pointer to the reserved space on success,
 * or NULL if the protobuf is being used to measure instead of write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
static int noise_protobuf_reserve_space
    (NoiseProtobuf *pbuf, size_t size, uint8_t **data)
{
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (size > pbuf->posn) {
        pbuf->error = NOISE_ERROR_INVALID_LENGTH;
        return pbuf->error;
    }
    pbuf->posn -= size;
    if (pbuf->data)
        *data = pbuf->data + pbuf->posn;
    else
        *data = 0;
    return NOISE_ERROR_NONE;
}

/** @cond */

#define NOISE_PROTOBUF_UINT64_BITS(n) (((uint64_t)1) << (n))

/** @endcond */

/**
 * \brief Writes a variable-length integer to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
static int noise_protobuf_write_varint(NoiseProtobuf *pbuf, uint64_t value)
{
    size_t size;
    uint8_t *data;
    int err;
    if (value < NOISE_PROTOBUF_UINT64_BITS(7))
        size = 1;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(14))
        size = 2;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(21))
        size = 3;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(28))
        size = 4;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(35))
        size = 5;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(42))
        size = 6;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(49))
        size = 7;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(56))
        size = 8;
    else if (value < NOISE_PROTOBUF_UINT64_BITS(63))
        size = 9;
    else
        size = 10;
    err = noise_protobuf_reserve_space(pbuf, size, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (!data)
        return NOISE_ERROR_NONE;
    while (size > 1) {
        *data++ = ((uint8_t)value) | (uint8_t)0x80;
        value >>= 7;
        --size;
    }
    *data = ((uint8_t)value) & (uint8_t)0x7F;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Writes a tag value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param type The wire representation type for the tag.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
static int noise_protobuf_write_tag(NoiseProtobuf *pbuf, int tag, int type)
{
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (!tag)
        return NOISE_ERROR_NONE;
    return noise_protobuf_write_varint
        (pbuf, (uint64_t)((((int64_t)tag) << NOISE_PROTOBUF_WIRE_BITS) |
                            (int64_t)type));
}

/**
 * \brief Writes a tagged integer value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
static int noise_protobuf_write_integer
    (NoiseProtobuf *pbuf, int tag, uint64_t value)
{
    int err = noise_protobuf_write_varint(pbuf, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    return noise_protobuf_write_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_VARINT);
}

/**
 * \brief Writes a tagged int32 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_int32(NoiseProtobuf *pbuf, int tag, int32_t value)
{
    return noise_protobuf_write_integer(pbuf, tag, (uint64_t)(int64_t)value);
}

/**
 * \brief Writes a tagged uint32 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_uint32(NoiseProtobuf *pbuf, int tag, uint32_t value)
{
    return noise_protobuf_write_integer(pbuf, tag, (uint64_t)value);
}

/**
 * \brief Writes a tagged int64 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_int64(NoiseProtobuf *pbuf, int tag, int64_t value)
{
    return noise_protobuf_write_integer(pbuf, tag, (uint64_t)value);
}

/**
 * \brief Writes a tagged uint64 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_uint64(NoiseProtobuf *pbuf, int tag, uint64_t value)
{
    return noise_protobuf_write_integer(pbuf, tag, value);
}

/**
 * \brief Writes a tagged sint32 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_sint32(NoiseProtobuf *pbuf, int tag, int32_t value)
{
    value = ((uint32_t)value << 1) ^ (value >> 31);
    return noise_protobuf_write_integer(pbuf, tag, (uint64_t)(uint32_t)value);
}

/**
 * \brief Writes a tagged sint64 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_sint64(NoiseProtobuf *pbuf, int tag, int64_t value)
{
    value = ((uint64_t)value << 1) ^ (value >> 63);
    return noise_protobuf_write_integer(pbuf, tag, (uint64_t)value);
}

/**
 * \brief Writes a tagged sfixed32 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_sfixed32(NoiseProtobuf *pbuf, int tag, int32_t value)
{
    return noise_protobuf_write_fixed32(pbuf, tag, (uint32_t)value);
}

/**
 * \brief Writes a tagged fixed32 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_fixed32(NoiseProtobuf *pbuf, int tag, uint32_t value)
{
    uint8_t *data;
    int err = noise_protobuf_reserve_space(pbuf, 4, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (data) {
        data[0] = (uint8_t)value;
        data[1] = (uint8_t)(value >> 8);
        data[2] = (uint8_t)(value >> 16);
        data[3] = (uint8_t)(value >> 24);
    }
    return noise_protobuf_write_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_32BIT);
}

/**
 * \brief Writes a tagged sfixed64 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_sfixed64(NoiseProtobuf *pbuf, int tag, int64_t value)
{
    return noise_protobuf_write_fixed64(pbuf, tag, (uint64_t)value);
}

/**
 * \brief Writes a tagged fixed64 value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The integer value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_fixed64(NoiseProtobuf *pbuf, int tag, uint64_t value)
{
    uint8_t *data;
    int err = noise_protobuf_reserve_space(pbuf, 8, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (data) {
        data[0] = (uint8_t)value;
        data[1] = (uint8_t)(value >> 8);
        data[2] = (uint8_t)(value >> 16);
        data[3] = (uint8_t)(value >> 24);
        data[4] = (uint8_t)(value >> 32);
        data[5] = (uint8_t)(value >> 40);
        data[6] = (uint8_t)(value >> 48);
        data[7] = (uint8_t)(value >> 56);
    }
    return noise_protobuf_write_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_64BIT);
}

/**
 * \brief Writes a tagged float value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The float value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_float(NoiseProtobuf *pbuf, int tag, float value)
{
    union {
        float fvalue;
        uint32_t ivalue;
    } volatile un;
    un.fvalue = value;
    return noise_protobuf_write_fixed32(pbuf, tag, un.ivalue);
}

/**
 * \brief Writes a tagged double value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The double value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_double(NoiseProtobuf *pbuf, int tag, double value)
{
    union {
        double fvalue;
        uint64_t ivalue;
    } volatile un;
    un.fvalue = value;
    return noise_protobuf_write_fixed64(pbuf, tag, un.ivalue);
}

/**
 * \brief Writes a tagged boolean value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param value The boolean value to write.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_bool(NoiseProtobuf *pbuf, int tag, int value)
{
    return noise_protobuf_write_integer(pbuf, tag, value ? 1 : 0);
}

/**
 * \brief Determine if a string is strict UTF-8.
 *
 * \param str Points to the string.
 * \param size The size of the string in bytes.
 *
 * \return Non-zero if the string is OK, zero if the string contains
 * bytes that are not compatible with strict UTF-8.
 *
 * Reference: https://tools.ietf.org/html/rfc3629
 */
static int noise_protobuf_is_utf8(const char *str, size_t size)
{
    uint8_t ch;
    uint32_t code;
    while (size > 0) {
        ch = *str++;
        --size;
        if (!ch) {
            /* Embedded NUL's are not allowed */
            return 0;
        } else if (ch < 0x80) {
            /* Ordinary character from the US-ASCII subset */
            continue;
        } else if (ch >= 0xC2 && ch <= 0xDF) {
            /* Two-byte UTF-8 sequence */
            if (size < 1)
                return 0;
            ch = *str++;
            --size;
            if (ch < 0x80 || ch > 0xBF)
                return 0;
        } else if (ch >= 0xE0 && ch <= 0xEF) {
            /* Three-byte UTF-8 sequence */
            if (size < 2)
                return 0;
            code = ((uint32_t)(ch & 0x0F)) << 12;
            ch = str[0];
            if (ch < 0x80 || ch > 0xBF)
                return 0;
            code |= ((uint32_t)(ch & 0x3F)) << 6;
            ch = str[1];
            if (ch < 0x80 || ch > 0xBF)
                return 0;
            code |= ((uint32_t)(ch & 0x3F));
            size -= 2;
            if (code >= 0xD800 && code <= 0xDFFF) {
                /* Surrogate pairs are not allowed */
                return 0;
            } else if (code < 0x0800) {
                /* Should have been represented as a 1 or 2 byte sequence */
                return 0;
            }
        } else if (ch >= 0xF0 && ch <= 0xF4) {
            /* Four-byte UTF-8 sequence */
            if (size < 3)
                return 0;
            code = ((uint32_t)(ch & 0x07)) << 18;
            ch = str[0];
            if (ch < 0x80 || ch > 0xBF)
                return 0;
            code |= ((uint32_t)(ch & 0x3F)) << 12;
            ch = str[1];
            if (ch < 0x80 || ch > 0xBF)
                return 0;
            code |= ((uint32_t)(ch & 0x3F)) << 6;
            ch = str[2];
            if (ch < 0x80 || ch > 0xBF)
                return 0;
            code |= ((uint32_t)(ch & 0x3F));
            size -= 3;
            if (code > 0x10FFFFUL) {
                /* Unicode code points stop at U+10FFFF */
                return 0;
            } else if (code < 0x10000) {
                /* Should have been represented as a 1 to 3 byte sequence */
                return 0;
            }
        } else {
            /* Invalid leading character for a UTF-8 sequence */
            return 0;
        }
    }
    return 1;
}

/**
 * \brief Writes a tagged UTF-8 string value to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param str Points to the string value to write, which can be NULL only
 * if \a size is zero.
 * \param size The size of the string in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a str is NULL and \a size is non-zero.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 * \return NOISE_ERROR_INVALID_FORMAT if \a str contains characters that are
 * not strict UTF-8.
 */
int noise_protobuf_write_string
    (NoiseProtobuf *pbuf, int tag, const char *str, size_t size)
{
    if (!pbuf || (!str && size))
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (!noise_protobuf_is_utf8(str, size)) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    return noise_protobuf_write_bytes(pbuf, tag, str, size);
}

/**
 * \brief Writes a tagged byte array to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param data Points to the byte array to write, which can be NULL only
 * if \a size is zero.
 * \param size The size of the byte array in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a data is NULL and \a size is non-zero.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 */
int noise_protobuf_write_bytes
    (NoiseProtobuf *pbuf, int tag, const void *data, size_t size)
{
    uint8_t *out_data;
    int err;
    if (!pbuf || (!data && size))
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_protobuf_reserve_space(pbuf, size, &out_data);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (out_data && size)
        memcpy(out_data, data, size);
    err = noise_protobuf_write_varint(pbuf, size);
    if (err != NOISE_ERROR_NONE)
        return err;
    return noise_protobuf_write_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
}

/**
 * \brief Writes the end of a nested element to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param end_posn Points to a variable to receive the end position
 * of the nested element.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a end_posn is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf is already out
 * of space.
 *
 * This function should be followed by calls to write the fields of
 * the nested element in reverse order.  After all fields have been
 * written, noise_protobuf_write_start_element() should be called to
 * finalize the nested element.
 *
 * \sa noise_protobuf_write_start_element()
 */
int noise_protobuf_write_end_element(NoiseProtobuf *pbuf, size_t *end_posn)
{
    if (end_posn)
        *end_posn = 0;
    if (!pbuf || !end_posn)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    *end_posn = pbuf->posn;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Writes the start of a tagged nested element to a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag value to write, or zero for no tag.
 * \param end_posn The end position that was returned from a previous
 * call to noise_protobuf_write_end_element().
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a end_posn is out of range.
 * \return NOISE_ERROR_INVALID_LENGTH if the protobuf has insufficient space.
 *
 * \sa noise_protobuf_write_end_element()
 */
int noise_protobuf_write_start_element
    (NoiseProtobuf *pbuf, int tag, size_t end_posn)
{
    int err;
    if (!pbuf || end_posn < pbuf->posn || end_posn > pbuf->size)
        return NOISE_ERROR_INVALID_PARAM;
    if (!tag)
        return pbuf->error; /* No tag or size field necessary */
    err = noise_protobuf_write_varint(pbuf, end_posn - pbuf->posn);
    if (err != NOISE_ERROR_NONE)
        return err;
    return noise_protobuf_write_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
}

/**
 * \brief Peeks at the next varint value in a protobuf.
 *
 * \param pbuf The protobuf.
 * \param value Variable to receive the variable on exit.
 * \param length On entry, the current length of the "peek area" at the
 * start of the field.  On exit, the new length of the peek area.
 *
 * \return NOISE_ERROR_NONE on sucess, or an error code otherwise.
 */
static int noise_protobuf_peek_varint
    (const NoiseProtobuf *pbuf, uint64_t *value, size_t *length)
{
    unsigned shift;
    uint8_t ch;
    size_t posn;
    *value = 0;
    if (!pbuf || !pbuf->data)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    posn = pbuf->posn + *length;
    if (posn >= pbuf->size)
        return NOISE_ERROR_INVALID_FORMAT;
    ch = pbuf->data[posn];
    ++(*length);
    if ((ch & 0x80) == 0) {
        *value = ch;
        return NOISE_ERROR_NONE;
    }
    *value = (ch & 0x7F);
    shift = 7;
    while (shift <= 63) {
        if (posn >= pbuf->size)
            return NOISE_ERROR_INVALID_FORMAT;
        ch = pbuf->data[posn++];
        *value |= (((uint64_t)(ch & 0x7F)) << shift);
        ++(*length);
        if ((ch & 0x80) == 0)
            return NOISE_ERROR_NONE;
        shift += 7;
    }
    return NOISE_ERROR_INVALID_FORMAT;
}

/**
 * \brief Peeks at the tag number for the next field in a protobuf.
 *
 * \param pbuf The protobuf.
 *
 * \return The tag number or zero if the format of the data in
 * \a pbuf is invalid.
 *
 * \sa noise_protobuf_peek_size()
 */
int noise_protobuf_peek_tag(const NoiseProtobuf *pbuf)
{
    uint64_t tag;
    size_t length = 0;
    int err = noise_protobuf_peek_varint(pbuf, &tag, &length);
    if (err != NOISE_ERROR_NONE)
        return 0;
    tag >>= NOISE_PROTOBUF_WIRE_BITS;
    if (!tag || tag > NOISE_PROTOBUF_MAX_TAG)
        return 0;
    if (sizeof(int) < sizeof(uint32_t)) {
        /* 16-bit or 8-bit embedded system with a limited tag range */
        if (tag > 32767)
            return 0;
    }
    return (int)tag;
}

/**
 * \brief Peeks at the size of the next field in a protobuf.
 *
 * \param pbuf The protobuf.
 *
 * \return The size of the next field, zero if the field is not
 * length-delimted, or zero if the format of the data in \a pbuf is invalid.
 *
 * This function is intended for determining the size of strings and
 * byte arrays before they are read with noise_protobuf_read_string()
 * or noise_protobuf_read_bytes() so that an appropriately-sized buffer
 * can be allocated for the value.
 *
 * \sa noise_protobuf_peek_tag()
 */
size_t noise_protobuf_peek_size(const NoiseProtobuf *pbuf)
{
    uint64_t value;
    size_t length = 0;
    int err = noise_protobuf_peek_varint(pbuf, &value, &length);
    if (err != NOISE_ERROR_NONE)
        return 0;
    if ((value & NOISE_PROTOBUF_WIRE_MASK) != NOISE_PROTOBUF_WIRE_DELIM)
        return 0;
    err = noise_protobuf_peek_varint(pbuf, &value, &length);
    if (err != NOISE_ERROR_NONE)
        return 0;
    if (sizeof(size_t) < sizeof(uint64_t)) {
        /* Range-check the value on systems with smaller size_t types */
        if ((value & (uint64_t)(~((size_t)0))) != value)
            return 0;
    }
    return (size_t)value;
}

/**
 * \brief Reads a variable-sized integer from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param value Points to the variable to receive the value.  Must not be NULL.
 *
 * \return NOISE_ERROR_NONE on success, or an error code otherwise.
 */
static int noise_protobuf_read_varint(NoiseProtobuf *pbuf, uint64_t *value)
{
    unsigned shift;
    uint8_t ch;
    *value = 0;
    if (!pbuf || !pbuf->data)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (pbuf->posn >= pbuf->size) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    ch = pbuf->data[(pbuf->posn++)];
    if ((ch & 0x80) == 0) {
        *value = ch;
        return NOISE_ERROR_NONE;
    }
    *value = (ch & 0x7F);
    shift = 7;
    while (shift <= 63) {
        if (pbuf->posn >= pbuf->size) {
            pbuf->error = NOISE_ERROR_INVALID_FORMAT;
            return pbuf->error;
        }
        ch = pbuf->data[(pbuf->posn++)];
        *value |= (((uint64_t)(ch & 0x7F)) << shift);
        if ((ch & 0x80) == 0)
            return NOISE_ERROR_NONE;
        shift += 7;
    }
    pbuf->error = NOISE_ERROR_INVALID_FORMAT;
    return pbuf->error;
}

/**
 * \brief Reads a tag value from a protobuf and matches it.
 *
 * \param pbuf The protobuf.
 * \param tag The expected tag value, or zero for no tag.
 * \param type The expected wire type.
 *
 * \return NOISE_ERROR_NONE on success, or an error code otherwise.
 */
static int noise_protobuf_read_tag(NoiseProtobuf *pbuf, int tag, int type)
{
    int err;
    if (tag > 0) {
        /* We expect a specific tag value and wire type to occur */
        uint64_t expected = (uint64_t)((((int64_t)tag) << 3) | (int64_t)type);
        uint64_t actual = 0;
        err = noise_protobuf_read_varint(pbuf, &actual);
        if (err == NOISE_ERROR_NONE) {
            if (expected != actual) {
                pbuf->error = NOISE_ERROR_INVALID_FORMAT;
                err = pbuf->error;
            }
        }
    } else if (tag == 0) {
        /* The caller-supplied tag is zero, which means no tag is expected */
        err = pbuf->error;
    } else {
        /* The caller-supplied tag is negative, which is always an error */
        if (pbuf->error != NOISE_ERROR_NONE)
            pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        err = pbuf->error;
    }
    return err;
}

/**
 * \brief Reads a certain number of raw bytes out of a protobuf.
 *
 * \param pbuf The protobuf.
 * \param size The number of bytes to read.
 * \param data Returns a pointer to the space on exit.
 *
 * \return NOISE_ERROR_NONE on success, or an error code otherwise.
 */
static int noise_protobuf_read_space
    (NoiseProtobuf *pbuf, size_t size, const uint8_t **data)
{
    if (!pbuf || !pbuf->data)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (size > (pbuf->size - pbuf->posn)) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    *data = pbuf->data + pbuf->posn;
    pbuf->posn += size;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged integer value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field.
 * \param value Variable that returns the integer value.
 * \param result_ptr The original return pointer from the parent function,
 * for validation.
 *
 * \return NOISE_ERROR_NONE on success, or an error code otherwise.
 */
static int noise_protobuf_read_integer
    (NoiseProtobuf *pbuf, int tag, uint64_t *value, void *result_ptr)
{
    int err;
    if (!pbuf || !result_ptr)
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_VARINT);
    if (err != NOISE_ERROR_NONE)
        return err;
    return noise_protobuf_read_varint(pbuf, value);
}

/**
 * \brief Reads a tagged int32 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an integer or the \a tag is incorrect.
 */
int noise_protobuf_read_int32(NoiseProtobuf *pbuf, int tag, int32_t *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = (int32_t)val;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged uint32 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an integer or the \a tag is incorrect.
 */
int noise_protobuf_read_uint32(NoiseProtobuf *pbuf, int tag, uint32_t *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = (uint32_t)val;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged int64 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an integer or the \a tag is incorrect.
 */
int noise_protobuf_read_int64(NoiseProtobuf *pbuf, int tag, int64_t *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = (int64_t)val;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged uint64 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an integer or the \a tag is incorrect.
 */
int noise_protobuf_read_uint64(NoiseProtobuf *pbuf, int tag, uint64_t *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = val;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged sint32 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an integer or the \a tag is incorrect.
 */
int noise_protobuf_read_sint32(NoiseProtobuf *pbuf, int tag, int32_t *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = ((int32_t)(val >> 1)) ^ (-((int32_t)(val & 0x01)));
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged sint64 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an integer or the \a tag is incorrect.
 */
int noise_protobuf_read_sint64(NoiseProtobuf *pbuf, int tag, int64_t *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = ((int64_t)(val >> 1)) ^ (-((int64_t)(val & 0x01)));
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged sfixed32 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a sfixed32 or the \a tag is incorrect.
 */
int noise_protobuf_read_sfixed32(NoiseProtobuf *pbuf, int tag, int32_t *value)
{
    return noise_protobuf_read_fixed32(pbuf, tag, (uint32_t *)value);
}

/**
 * \brief Reads a tagged fixed32 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a fixed32 or the \a tag is incorrect.
 */
int noise_protobuf_read_fixed32(NoiseProtobuf *pbuf, int tag, uint32_t *value)
{
    int err;
    const uint8_t *data;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_32BIT);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_read_space(pbuf, 4, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = ((uint32_t)(data[0])) |
            (((uint32_t)(data[1])) << 8) |
            (((uint32_t)(data[2])) << 16) |
            (((uint32_t)(data[3])) << 24);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged sfixed64 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a sfixed64 or the \a tag is incorrect.
 */
int noise_protobuf_read_sfixed64(NoiseProtobuf *pbuf, int tag, int64_t *value)
{
    return noise_protobuf_read_fixed64(pbuf, tag, (uint64_t *)value);
}

/**
 * \brief Reads a tagged fixed64 value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the integer value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a fixed64 or the \a tag is incorrect.
 */
int noise_protobuf_read_fixed64(NoiseProtobuf *pbuf, int tag, uint64_t *value)
{
    int err;
    const uint8_t *data;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_64BIT);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_read_space(pbuf, 8, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = ((uint64_t)(data[0])) |
            (((uint64_t)(data[1])) << 8) |
            (((uint64_t)(data[2])) << 16) |
            (((uint64_t)(data[3])) << 24) |
            (((uint64_t)(data[4])) << 32) |
            (((uint64_t)(data[5])) << 40) |
            (((uint64_t)(data[6])) << 48) |
            (((uint64_t)(data[7])) << 56);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged float value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the floating-point value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a float or the \a tag is incorrect.
 */
int noise_protobuf_read_float(NoiseProtobuf *pbuf, int tag, float *value)
{
    union {
        uint32_t ivalue;
        float fvalue;
    } un;
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    un.ivalue = 0;
    err = noise_protobuf_read_fixed32(pbuf, tag, &(un.ivalue));
    if (err == NOISE_ERROR_NONE)
        *value = un.fvalue;
    else
        *value = 0.0f;
    return err;
}

/**
 * \brief Reads a tagged double value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the floating-point value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a double or the \a tag is incorrect.
 */
int noise_protobuf_read_double(NoiseProtobuf *pbuf, int tag, double *value)
{
    union {
        uint64_t ivalue;
        double fvalue;
    } un;
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    un.ivalue = 0;
    err = noise_protobuf_read_fixed64(pbuf, tag, &(un.ivalue));
    if (err == NOISE_ERROR_NONE)
        *value = un.fvalue;
    else
        *value = 0.0;
    return err;
}

/**
 * \brief Reads a tagged boolean value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param value Variable that returns the boolean value.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a value is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for an boolean or the \a tag is incorrect.
 */
int noise_protobuf_read_bool(NoiseProtobuf *pbuf, int tag, int *value)
{
    uint64_t val = 0;
    int err;
    if (value)
        *value = 0;
    err = noise_protobuf_read_integer(pbuf, tag, &val, value);
    if (err != NOISE_ERROR_NONE)
        return err;
    *value = (val != 0);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged string value from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param str The buffer to write the string value to.
 * \param max_size The maximum size of \a str in bytes.
 * \param size Points to a variable to receive the actual size of the
 * string, excluding the NUL terminator.  This argument may be NULL
 * if the application does not need the size.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a str is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a max_size is zero.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a UTF-8 string or the \a tag is incorrect.
 *
 * This function guarantees to NUL-terminate the value in \a str if
 * \a str is not NULL and \a max_size is non-zero.
 *
 * This function will validate the incoming data to ensure that it is
 * strict UTF-8 with no embedded NUL's.
 *
 * \sa noise_protobuf_read_alloc_string(), noise_protobuf_read_bytes()
 */
int noise_protobuf_read_string
    (NoiseProtobuf *pbuf, int tag, char *str, size_t max_size, size_t *size)
{
    int err;
    uint64_t value;
    size_t sz;
    const uint8_t *data;
    if (!str || !max_size)
        return NOISE_ERROR_INVALID_PARAM;
    *str = '\0';
    if (size)
        *size = 0;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_read_varint(pbuf, &value);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (value >= max_size) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    sz = (size_t)value;
    err = noise_protobuf_read_space(pbuf, sz, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (!noise_protobuf_is_utf8((const char *)data, sz)) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    memcpy(str, data, sz);
    str[sz] = '\0';
    if (size)
        *size = sz;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged string value from a protobuf and allocates
 * memory from the heap to hold it.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param str Points to a variable to receive the pointer to the newly
 * allocated memory.
 * \param max_size The maximum allowable size for the string if non-zero,
 * excluding the NUL-terminator.  If \a max_size is zero, then the
 * allowable string size is unlimited.
 * \param size Points to a variable to receive the actual size of the
 * string, excluding the NUL terminator.  This argument may be NULL
 * if the application does not need the size.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a str is NULL.
 * \return NOISE_ERROR_INVALID_PARAM if \a max_size is zero.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is invalid
 * for a UTF-8 string or the \a tag is incorrect.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to allocate
 * the string.
 *
 * This function will validate the incoming data to ensure that it is
 * strict UTF-8 with no embedded NUL's.
 *
 * The memory is allocated with the system malloc() function.
 *
 * \sa noise_protobuf_read_string(), noise_protobuf_read_alloc_bytes()
 */
int noise_protobuf_read_alloc_string
    (NoiseProtobuf *pbuf, int tag, char **str, size_t max_size, size_t *size)
{
    int err;
    uint64_t value;
    size_t sz;
    const uint8_t *data;
    if (!str)
        return NOISE_ERROR_INVALID_PARAM;
    *str = 0;
    if (size)
        *size = 0;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_read_varint(pbuf, &value);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (!max_size)
        max_size = pbuf->size - pbuf->posn;
    if (value > max_size) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    sz = (size_t)value;
    err = noise_protobuf_read_space(pbuf, sz, &data);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (!noise_protobuf_is_utf8((const char *)data, sz)) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    if ((*str = (char *)malloc(sz + 1)) == 0) {
        pbuf->error = NOISE_ERROR_NO_MEMORY;
        return pbuf->error;
    }
    memcpy(*str, data, sz);
    (*str)[sz] = '\0';
    if (size)
        *size = sz;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged byte array from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param data The buffer to write the byte array data to.
 * \param max_size The maximum size of \a data in bytes.
 * \param size Points to a variable to receive the actual size of the
 * byte array.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf, \a data, or \a size is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is larger
 * than \a max_size or the \a tag is incorrect.
 *
 * \sa noise_protobuf_read_alloc_bytes(), noise_protobuf_read_string()
 */
int noise_protobuf_read_bytes
    (NoiseProtobuf *pbuf, int tag, void *data, size_t max_size, size_t *size)
{
    int err;
    uint64_t value;
    size_t sz;
    const uint8_t *d;
    if (!data || !size)
        return NOISE_ERROR_INVALID_PARAM;
    *size = 0;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_read_varint(pbuf, &value);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (value > max_size) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    sz = (size_t)value;
    err = noise_protobuf_read_space(pbuf, sz, &d);
    if (err != NOISE_ERROR_NONE)
        return err;
    memcpy(data, d, sz);
    if (size)
        *size = sz;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Reads a tagged byte array from a protobuf and allocates memory
 * from the heap to hold it.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param data Points to a variable to receive the pointer to the newly
 * allocated memory.
 * \param max_size The maximum allowable size for the byte array if non-zero.
 * If \a max_size is zero, then the allowable byte array size is unlimited.
 * \param size Points to a variable to receive the actual size of the
 * byte array.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf, \a data, or \a size is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is larger
 * than \a max_size or the \a tag is incorrect.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to allocate
 * the byte array.
 *
 * The memory is allocated with the system malloc() function.
 *
 * \sa noise_protobuf_read_alloc_string(), noise_protobuf_read_bytes()
 */
int noise_protobuf_read_alloc_bytes
    (NoiseProtobuf *pbuf, int tag, void **data, size_t max_size, size_t *size)
{
    int err;
    uint64_t value;
    size_t sz;
    const uint8_t *d;
    if (!data || !size)
        return NOISE_ERROR_INVALID_PARAM;
    *data = 0;
    if (size)
        *size = 0;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_read_varint(pbuf, &value);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (!max_size)
        max_size = pbuf->size - pbuf->posn;
    if (value > max_size) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    sz = (size_t)value;
    err = noise_protobuf_read_space(pbuf, sz, &d);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (sz > 0) {
        if ((*data = malloc(sz)) == 0) {
            pbuf->error = NOISE_ERROR_NO_MEMORY;
            return pbuf->error;
        }
        memcpy(*data, d, sz);
    } else {
        /* malloc() may return NULL for a zero size: prevent that */
        if ((*data = malloc(1)) == 0) {
            pbuf->error = NOISE_ERROR_NO_MEMORY;
            return pbuf->error;
        }
        ((uint8_t *)(*data))[0] = '\0';
    }
    if (size)
        *size = sz;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Starts reading a tagged nested element from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param tag The tag that is expected on the field, or zero for no tag.
 * \param end_posn Points to a variable to receive the position of the
 * end of the nested element.  This is used by noise_protobuf_read_end_element()
 * and noise_protobuf_read_at_end_element() to determine if the end of
 * the nested element has been reached yet.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf or \a end_posn is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf is not formatted
 * correctly for a nested element, or the \a tag is incorrect.
 *
 * \sa noise_protobuf_read_end_element(), noise_protobuf_read_at_end_element()
 */
int noise_protobuf_read_start_element
    (NoiseProtobuf *pbuf, int tag, size_t *end_posn)
{
    int err;
    uint64_t size;
    if (!pbuf || !end_posn)
        return NOISE_ERROR_INVALID_PARAM;
    *end_posn = 0;
    err = noise_protobuf_read_tag(pbuf, tag, NOISE_PROTOBUF_WIRE_DELIM);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (tag) {
        err = noise_protobuf_read_varint(pbuf, &size);
        if (err != NOISE_ERROR_NONE)
            return err;
        if (size > (pbuf->size - pbuf->posn)) {
            pbuf->error = NOISE_ERROR_INVALID_FORMAT;
            return pbuf->error;
        }
        *end_posn = pbuf->posn + size;
    } else {
        /* No tag, so the element continues until the end of the buffer */
        *end_posn = pbuf->size;
    }
    return NOISE_ERROR_NONE;
}

/**
 * \brief Ends reading a nested element from a protobuf.
 *
 * \param pbuf The protobuf.
 * \param end_posn The end of the nested element as returned by
 * noise_protobuf_read_start_element().
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if \a pbuf is not positioned at
 * exactly \a end_posn.
 *
 * \sa noise_protobuf_read_start_element(), noise_protobuf_read_at_end_element()
 */
int noise_protobuf_read_end_element(NoiseProtobuf *pbuf, size_t end_posn)
{
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;
    if (pbuf->posn != end_posn) {
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        return pbuf->error;
    }
    return NOISE_ERROR_NONE;
}

/**
 * \brief Determine if a protobuf is positioned at the end of a nested element.
 *
 * \param pbuf The protobuf.
 * \param end_posn The end of the nested element as returned by
 * noise_protobuf_read_start_element().
 *
 * \return Returns 1 if the position is past \a end_posn in \a pbuf or an
 * error has already occurred.  Returns 0 if the position has not yet reached
 * \a end_posn.
 *
 * \sa noise_protobuf_read_start_element(), noise_protobuf_read_end_element()
 */
int noise_protobuf_read_at_end_element
    (const NoiseProtobuf *pbuf, size_t end_posn)
{
    if (!pbuf || pbuf->error != NOISE_ERROR_NONE)
        return 1;
    return pbuf->posn >= end_posn;
}

/**
 * \brief Stops reading from a protobuf and reports "invalid format".
 *
 * \param pbuf The protobuf.
 *
 * \return NOISE_ERROR_INVALID_PARAM if \a pbuf is NULL, or
 * NOISE_ERROR_INVALID_FORMAT otherwise.
 *
 * The application calls this function to abort the reading process because
 * an unrecoverable error has occurred.
 *
 * \note If an error has already occurred during the reading process, then
 * this function returns that error rather than NOISE_ERROR_INVALID_FORMAT.
 *
 * \sa noise_protobuf_read_skip()
 */
int noise_protobuf_read_stop(NoiseProtobuf *pbuf)
{
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    if (pbuf->error == NOISE_ERROR_NONE)
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
    return pbuf->error;
}

/**
 * \brief Skips a tagged field within a protobuf completely.
 *
 * \param pbuf The protobuf.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_FORMAT if the data in \a pbuf to be skipped
 * is not correctly formatted as a field.
 *
 * The application should call this function for unknown fields so as to
 * skip them and move onto the next field.  If the application wishes to
 * abort on an unknown field, it should call noise_protobuf_read_stop()
 * instead.
 *
 * \sa noise_protobuf_read_stop()
 */
int noise_protobuf_read_skip(NoiseProtobuf *pbuf)
{
    uint64_t value;
    const uint8_t *data;
    int err;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_protobuf_read_varint(pbuf, &value);
    if (err != NOISE_ERROR_NONE)
        return err;
    switch (value & NOISE_PROTOBUF_WIRE_MASK) {
    case NOISE_PROTOBUF_WIRE_VARINT:
        err = noise_protobuf_read_varint(pbuf, &value);
        break;
    case NOISE_PROTOBUF_WIRE_64BIT:
        err = noise_protobuf_read_space(pbuf, 8, &data);
        break;
    case NOISE_PROTOBUF_WIRE_DELIM:
        err = noise_protobuf_read_varint(pbuf, &value);
        if (err == NOISE_ERROR_NONE) {
            if (value <= (pbuf->size - pbuf->posn)) {
                pbuf->posn += value;
            } else {
                pbuf->error = NOISE_ERROR_INVALID_FORMAT;
                err = pbuf->error;
            }
        }
        break;
    case NOISE_PROTOBUF_WIRE_32BIT:
        err = noise_protobuf_read_space(pbuf, 4, &data);
        break;
    default:
        pbuf->error = NOISE_ERROR_INVALID_FORMAT;
        err = pbuf->error;
        break;
    }
    return err;
}

/**
 * \brief Grows the size of a dynamically-sized array.
 *
 * \param max The current maximum size.
 *
 * \return The new maximum size.
 */
static size_t noise_protobuf_grow_array(size_t max)
{
    if (max >= 64)
        max += 64;
    else if (max)
        max *= 2;
    else
        max = 4;
    return max;
}

/**
 * \brief Adds an element to an array of primitive values.
 *
 * \param array Points to the array to add to.
 * \param count Points to the current size of the array.
 * \param max Points to the current maximum size of the array.
 * \param value Points to the value to add.
 * \param size Size of the elements in the array.
 *
 * \return NOISE_ERROR_NONE on success or an error code otherwise.
 *
 * This function is intended as a helper for the output of the
 * noise-protoc complier.
 *
 * \sa noise_protobuf_add_to_string_array(), noise_protobuf_add_to_bytes_array()
 */
int noise_protobuf_add_to_array
    (void **array, size_t *count, size_t *max, const void *value, size_t size)
{
    if (*count >= *max) {
        size_t new_max = noise_protobuf_grow_array(*max);
        void *new_array = calloc(new_max, size);
        if (!new_array)
            return NOISE_ERROR_NO_MEMORY;
        if (*count)
            memcpy(new_array, *array, *count * size);
        noise_protobuf_free_memory(*array, *max * size);
        *array = new_array;
        *max = new_max;
    }
    memcpy(((uint8_t *)(*array)) + *count * size, value, size);
    ++(*count);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Internal implementation of noise_protobuf_add_to_string_array()
 * and noise_protobuf_add_to_bytes_array()
 */
static int noise_protobuf_add_to_block_array
    (void ***array, size_t **len_array, size_t *count, size_t *max,
     const void *value, size_t size, int add_nul)
{
    void *data;

    /* Bail out if the value to add is NULL and non-zero in size */
    if (!value && size)
        return NOISE_ERROR_INVALID_PARAM;

    /* Make a copy of the value first */
    data = malloc(size + (add_nul ? 1 : 0));
    if (!data)
        return NOISE_ERROR_NO_MEMORY;
    if (size)
        memcpy(data, value, size);
    if (add_nul)
        ((uint8_t *)data)[size] = 0;

    /* Grow the size of the array if necessary */
    if (*count >= *max) {
        size_t new_max = noise_protobuf_grow_array(*max);
        void **new_array = (void **)calloc(new_max, sizeof(void *));
        size_t *new_len_array = (size_t *)calloc(new_max, sizeof(size_t));
        if (!new_array || !new_len_array) {
            if (new_array)
                free(new_array);
            if (new_len_array)
                free(new_len_array);
            noise_protobuf_free_memory(data, size);
            return NOISE_ERROR_NO_MEMORY;
        }
        if (*count) {
            memcpy(new_array, *array, *count * sizeof(void *));
            memcpy(new_len_array, *len_array, *count * sizeof(size_t));
        }
        noise_protobuf_free_memory(*array, *max * sizeof(void *));
        noise_protobuf_free_memory(*len_array, *max * sizeof(size_t));
        *array = new_array;
        *len_array = new_len_array;
        *max = new_max;
    }

    /* Add the new element to the array */
    (*array)[*count] = data;
    (*len_array)[*count] = size;
    ++(*count);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Adds a string to a dynamically-sized array.
 *
 * \param array Points to the array to add to.
 * \param len_array Points to the array of length values to add to.
 * \param count Points to the current size of the array.
 * \param max Points to the current maximum size of the array.
 * \param value Points to the string value to add.
 * \param size Size of the string value to add.
 *
 * \return NOISE_ERROR_NONE on success or an error code otherwise.
 *
 * This function is intended as a helper for the output of the
 * noise-protoc complier.
 *
 * \sa noise_protobuf_add_to_array(), noise_protobuf_add_to_bytes_array()
 */
int noise_protobuf_add_to_string_array
    (char ***array, size_t **len_array, size_t *count, size_t *max,
     const char *value, size_t size)
{
    return noise_protobuf_add_to_block_array
        ((void ***)array, len_array, count, max, value, size, 1);
}

/**
 * \brief Adds a byte string to a dynamically-sized array.
 *
 * \param array Points to the array to add to.
 * \param len_array Points to the array of length values to add to.
 * \param count Points to the current size of the array.
 * \param max Points to the current maximum size of the array.
 * \param value Points to the byte string value to add.
 * \param size Size of the byte string value to add.
 *
 * \return NOISE_ERROR_NONE on success or an error code otherwise.
 *
 * This function is intended as a helper for the output of the
 * noise-protoc complier.
 *
 * \sa noise_protobuf_add_to_array(), noise_protobuf_add_to_string_array()
 */
int noise_protobuf_add_to_bytes_array
    (void ***array, size_t **len_array, size_t *count, size_t *max,
     const void *value, size_t size)
{
    return noise_protobuf_add_to_block_array
        (array, len_array, count, max, value, size, size ? 0 : 1);
}

/**
 * \brief Inserts an item into a dynamically-sized array.
 *
 * \param array Points to the array to add to.
 * \param len_array Points to the array of length values to add to.
 * \param count Points to the current size of the array.
 * \param max Points to the current maximum size of the array.
 * \param index The index within the array to insert at.  If this is
 * greater than the size of the array, the value will be appended.
 * \param value Points to the value to add.
 * \param size Size of the elements in the array.
 *
 * \return NOISE_ERROR_NONE on success or an error code otherwise.
 *
 * This function is intended as a helper for the output of the
 * noise-protoc complier.
 */
int noise_protobuf_insert_into_array
    (void **array, size_t *count, size_t *max, size_t index,
     const void *value, size_t size)
{
    uint8_t *base;

    /* Handle the easy case first - inserting at the end of the array */
    if (index >= *count) {
        return noise_protobuf_add_to_array
            (array, count, max, value, size);
    }

    /* Grow the array size if necessary */
    if (*count >= *max) {
        size_t new_max = noise_protobuf_grow_array(*max);
        void *new_array = calloc(new_max, size);
        if (!new_array)
            return NOISE_ERROR_NO_MEMORY;
        if (*count)
            memcpy(new_array, *array, *count * size);
        noise_protobuf_free_memory(*array, *max * size);
        *array = new_array;
        *max = new_max;
    }

    /* Move existing items out of the way and insert the new one */
    base = (uint8_t *)(*array);
    memmove(base + (index + 1) * size, base + index * size,
            (*count - index) * size);
    memcpy(base + index * size, value, size);
    ++(*count);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Frees a block of memory after securely clearing it.
 *
 * \param ptr Points to the block of memory.
 * \param size The size of the block in bytes.
 *
 * This function uses the system free() function to free \a ptr.
 */
void noise_protobuf_free_memory(void *ptr, size_t size)
{
    if (ptr) {
        volatile uint8_t *p = (volatile uint8_t *)ptr;
        while (size > 0) {
            *p++ = 0;
            --size;
        }
        free(ptr);
    }
}

/**@}*/
