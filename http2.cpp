/* (c) 2019 Justin Jack - MIT License */

#include "http2.h"
#include "http2_debug.h"
#include "showbits.h"

/*
 * Todos:
 * -----------------------------------------------------------------------------
 * Implement errno or similar to allow functions that return NULL pointers
 * indicating errors to be more explicit as to what went wrong.
 * 
 */


uint8_t *http2_build_frame( 
        HTTP2_FRAME_TYPE ft, 
        uint8_t flags, 
        uint32_t stream_id,
        size_t payload_length, 
        void *payload,
        size_t *frame_size_out) {
    uint8_t *pframe = 0, *ppayload = 0;
    size_t fs_out = 9;
    if (!frame_size_out) {
        http2_error("NULL pointer received for size_t *frame_size_out!\n");
        return 0;
    }
    *frame_size_out = 0;
    /* When building a frame, we need to check the 
     * peer's settings and make sure we're within their settings.
     **/
    
    if (payload_length > 0x00FFFFFF) {
        http2_error("Frame payloads cannot exceed 24 bit lengths.\n");
        return 0;
    }

    // HTTP/2 Frame Header
    //
    // 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 ...
    // 0        1        2        3        4        5        6        7        8        9        10
    // <-------- Length --------> <-Type-> <-Flag-> <---------- Stream ID  -----------> <----- Data ...
    
    
    switch (ft) {
        case HTTP2_FRAME_GOAWAY:
            fs_out = fs_out + sizeof(uint32_t);
            *frame_size_out = fs_out;
            pframe = (uint8_t *)malloc(fs_out);
            if (!pframe) {
                http2_error("Failed to allocate %zu bytes to build HTTP/2 frame.\n", fs_out);
            }
            
            http2_zero(pframe, fs_out);
            
            *(uint32_t *)&pframe[0]     = 0x0400;
            * (uint8_t *)&pframe[3]     = (uint8_t)ft;
            *(uint32_t *)&pframe[9]     = htonl(*((uint32_t *)payload));
            break;
        case HTTP2_FRAME_SETTINGS:
            fs_out = (fs_out + payload_length);
            *frame_size_out = fs_out;
            pframe = (uint8_t *)malloc(fs_out);
            if (!pframe) {
                http2_error("Failed to allocate %zu bytes to build HTTP/2 frame.\n", fs_out);
            }
            http2_zero(pframe, fs_out);
            http2_debug(HTTP2_VERY_IMPORTANT, "Allocated %zu bytes for SETTINGS frame. That's 9 for the header, and %zu for the payload length\n", fs_out, payload_length);
            
            
            *(uint32_t *)&pframe[0] = htonl((payload_length<<8));
            
            * (uint8_t *)&pframe[3] = (uint8_t)ft;
            * (uint8_t *)&pframe[4] = flags;
            *(uint32_t *)&pframe[5] = htonl(stream_id << 1);

            if (payload_length > 0) {
                memcpy((void *)&pframe[9], payload, payload_length);
            }
            break;
        case HTTP2_FRAME_RST_STREAM: /* Kill the stream, there was an error.
                                      * 'payload' points to a uint32_t error
                                      * value.
                                      **/
            fs_out = fs_out + sizeof(uint32_t);
            *frame_size_out = fs_out;
            pframe = (uint8_t *)malloc(fs_out);
            if (!pframe) {
                http2_error("Failed to allocate %zu bytes to build HTTP/2 frame.\n", fs_out);
            }
            http2_zero(pframe, fs_out);
            *(uint32_t *)&pframe[0]     = 0x0400;
            * (uint8_t *)&pframe[3]     = (uint8_t)ft;
            *(uint32_t *)&pframe[5]     = htonl(stream_id << 1);
            *(uint32_t *)&pframe[9]     = htonl(*((uint32_t *)payload));
            
            break;
        default:
            http2_error("We've been asked to build an unknown frame type.\n");
            break;
    }
    printf("\n\n<============ Sending FRAME ====================>\n");
    shownbits(pframe, 9);
    printf("\n<====================================================>\n\n");
    return pframe;
}

int http2_buffer_output( PHTTP2_CONNECTION c, void *pdata, size_t len_data) {
    uint8_t *swap = 0;
    size_t swap_len = 0;
    if (!pdata || len_data == 0) return 0;
    http2_lock( c->output_buffer_mutex);
    if (c->output_len + len_data > c->output_buffer_size ) {
        http2_debug(HTTP2_VERY_IMPORTANT, "Increasing connection's output buffer size.\n");
        swap_len = c->output_buffer_size + len_data + 0xFFFF;
        swap = (uint8_t *)realloc(c->output_buffer, swap_len);
        if (!swap) {
            http2_unlock( c->output_buffer_mutex );
            return 0;
        }
        c->output_buffer = swap;
        c->output_buffer_size = swap_len;
    }
    memcpy(&c->output_buffer[c->output_len], pdata, len_data);
    c->output_len+=len_data;
    http2_unlock( c->output_buffer_mutex);
    http2_tcp_output_available();
    free(pdata);
    return 1;
}

void http2_reset_stream( PHTTP2_STREAM s, HTTP2_ERROR_CODE error) {
    void *frame_out = 0, *swap = 0;
    size_t frame_size_out = 0, swap_len = 0;
    frame_out = http2_build_frame(HTTP2_FRAME_RST_STREAM, 0, s->stream_id, 4, &error, &frame_size_out);
    if (!frame_out || frame_size_out == 0) {
        http2_error("Failed to build output frame!\n");
        return;
    }
    if (!http2_buffer_output(s->pconnection, frame_out, frame_size_out)) {
        http2_error("Failed to allocate more output buffer space for stream %lu!\n", s->stream_id);
        return;
    }
    return;
}

void http2_process_settings_frame( PHTTP2_CONNECTION c, uint32_t stream_id, uint8_t *pdata, size_t data_len) {
    uint16_t identifier = 0;
    uint32_t value = 0;
    struct _http2_settings *s = 0;
    int i = 0, sc = (data_len/6), j = 0;
    uint8_t *pack = 0;
    size_t ack_len = 0;
    if (!pdata) return;
    
    if (stream_id == 0) {
        s = &c->remote_connection_settings;
    } else {
        if (c->streams) {
            for (; c->streams[j]; j++) {
                if (c->streams[j]->stream_id == stream_id) {
                    s = &c->streams[j]->remote_stream_settings;
                    break;
                }
            }
        }
    }
    
    if (s == 0) {
        http2_error("Failed to find a stream with the ID of %lu on this connection for which to adjust SETTINGS!\n");
        return;
    }
    
//    printf("pdata=0x%x\n", pdata);
//    printf("length=%u\n", data_len);
    
    for (; i < sc; i++) {
//        printf("<------ SETTINGS --------->\n");
//        shownbits(&pdata[i*6], 6);
//        printf("\n<-------------------------------->\n");
        identifier = ntohs(*(uint16_t *)&pdata[i*6]);
        value      = ntohl(*(uint32_t *)&pdata[(i*6)+2]);
        switch (identifier) {
            case SETTINGS_HEADER_TABLE_SIZE:
                s->SETTINGS_HEADER_TABLE_SIZE = value;
//                http2_debug(HTTP2_PROCESS_SETTINGS_FRAME, "SETTINGS_HEADER_TABLE_SIZE: %lu\n", value);
                break;
            case SETTINGS_ENABLE_PUSH:
                s->SETTINGS_ENABLE_PUSH = value;
                http2_debug(HTTP2_PROCESS_SETTINGS_FRAME, "SETTINGS_ENABLE_PUSH: %lu\n", value);
                break;
            case SETTINGS_MAX_CONCURRENT_STREAMS:
                s->SETTINGS_MAX_CONCURRENT_STREAMS = value;
//                http2_debug(HTTP2_PROCESS_SETTINGS_FRAME, "SETTINGS_MAX_CONCURRENT_STREAMS: %lu\n", value);
                break;
            case SETTINGS_INITIAL_WINDOW_SIZE:
                s->SETTINGS_INITIAL_WINDOW_SIZE = value;
//                http2_debug(HTTP2_PROCESS_SETTINGS_FRAME, "SETTINGS_INITIAL_WINDOW_SIZE: %lu\n", value);
                break;
            case SETTINGS_MAX_FRAME_SIZE:
                
                if (value > 16777215 || value < 16384 ) {
                    uint32_t ecode = 0x01;
                    http2_error("Invalid SETTINGS_MAX_FRAME_SIZE")
                    pack = http2_build_frame(HTTP2_FRAME_GOAWAY, 0x00, 0, 4, (void *)&ecode, &ack_len);
                    http2_buffer_output(c, pack, ack_len);
                    usleep(500000); /* We're disconnecting.  Let this thread rest for 1/2 second before we shut 'er down */
                    c->connection_is_valid = 0;
                    return;
                }
                
                
                s->SETTINGS_MAX_FRAME_SIZE = value;
//                http2_debug(HTTP2_PROCESS_SETTINGS_FRAME, "SETTINGS_MAX_FRAME_SIZE: %lu\n", value);
                break;
            case SETTINGS_MAX_HEADER_LIST_SIZE:
                s->SETTINGS_MAX_HEADER_LIST_SIZE = value;
//                http2_debug(HTTP2_PROCESS_SETTINGS_FRAME, "SETTINGS_MAX_HEADER_LIST_SIZE: %lu\n", value);
                break;
            default:
                http2_debug(HTTP2_VERY_IMPORTANT,"Invalid Identifier value: 0x%x (%u) = %lu\n", identifier, identifier, value);
                break;
        }
    }
    
    pack = http2_build_frame(HTTP2_FRAME_SETTINGS, 0x01, stream_id, 0, 0, &ack_len);
    http2_buffer_output(c, pack, ack_len);
    
}

void http2_connection_error( PHTTP2_CONNECTION c, uint32_t error_code) {
    void *out = 0;
    size_t outlen = 0;
    uint32_t err_code = htonl(error_code);
    out = http2_build_frame(HTTP2_FRAME_GOAWAY, 0, 0, 4, &err_code, &outlen);
    http2_buffer_output(c, out, outlen);
    usleep(500000);
    c->connection_is_valid = 0;
    return;
}

void http2_stream_error(PHTTP2_CONNECTION c, uint32_t stream_id, uint32_t error_code) {
    void *out = 0;
    size_t outlen = 0;
    uint32_t err_code = htonl(error_code);
    out = http2_build_frame(HTTP2_FRAME_GOAWAY, 0, stream_id, 4, &err_code, &outlen);
    http2_buffer_output(c, out, outlen);
    return;
}

int http2_connection_send_settings(PHTTP2_CONNECTION c) {
    uint8_t settings[18];
    uint16_t *setting_id = 0;
    uint32_t *setting_value = 0;
    void *frame_out = 0;
    size_t frame_out_size = 0;
    
    http2_zero(settings, 18);
    
    setting_id      = (uint16_t *)&settings[0];
    setting_value   = (uint32_t *)&settings[2]; 
    *setting_id     = htons(SETTINGS_HEADER_TABLE_SIZE);
    *setting_value  = htonl(c->local_connection_settings.SETTINGS_HEADER_TABLE_SIZE);

    
    setting_id      = (uint16_t *)&settings[6];
    setting_value   = (uint32_t *)&settings[8];
    *setting_id     = htons(SETTINGS_INITIAL_WINDOW_SIZE);
    *setting_value  = htonl(c->local_connection_settings.SETTINGS_INITIAL_WINDOW_SIZE);
    
    
    setting_id      = (uint16_t *)&settings[12];
    setting_value   = (uint32_t *)&settings[14];
    *setting_id     = htons(SETTINGS_MAX_FRAME_SIZE);
    *setting_value  = htonl(c->local_connection_settings.SETTINGS_MAX_FRAME_SIZE);
    
    frame_out = http2_build_frame(HTTP2_FRAME_SETTINGS, 0, 0, 18, settings, &frame_out_size);
    http2_buffer_output(c, frame_out, frame_out_size);
    return 1;
}

void http2_process_window_update( PHTTP2_CONNECTION c, uint32_t stream_id, uint32_t *pdata) {
    uint32_t *window_size = 0;
    uint32_t new_value = 0;
    void *out = 0;
    size_t outlen = 0;
    int i = 0;
    
    if (!pdata) return;
    new_value = ntohl(*pdata) >> 1;
    
    if (new_value == 0) {
        http2_connection_error(c, HTTP2_ERROR_PROTOCOL_ERROR);
        return;
    }
    
    if (stream_id > 0) {
        if (c->streams) {
            for (; c->streams[i]; i++) {
                if (c->streams[i]->stream_id == stream_id) {
                    window_size = &c->streams[i]->peer_window_size;
                    break;
                }
            }
        }
        if (!window_size) {
            http2_stream_error(c, stream_id, HTTP2_ERROR_STREAM_CLOSED);
            return;
        }
    } else {
        window_size = &c->peer_window_size;
    }
    printf("\n\nAdding: %lu bytes to receiver's window.\n\n", new_value);
    *window_size=new_value;
}

PHTTP2_STREAM http2_connection_add_stream(PHTTP2_CONNECTION c, uint32_t stream_id) {
    PHTTP2_STREAM new_stream = 0, *swap = 0;
    size_t new_size = 0, i = 0, j = 0, streams_to_allocate = 0;
    
    
    if (c->local_connection_settings.SETTINGS_MAX_CONCURRENT_STREAMS == 0 ) {
        return 0;
    }
    
    
    
    
    new_stream = (PHTTP2_STREAM)malloc(sizeof(HTTP2_STREAM));
    if (!new_stream) return 0;
    huffman_zero_mem(new_stream, sizeof(HTTP2_STREAM));
    

    /* Build new HPACK table */
    new_stream->decoding_table.table = (PHTTP2_DYN_TABLE)malloc( (sizeof(HTTP2_DYN_TABLE) * http2_header_table_prototype.size) );
    new_stream->decoding_table.size = http2_header_table_prototype.size;
    new_stream->decoding_table.used = http2_header_table_prototype.used;
    memcpy(new_stream->decoding_table.table, http2_header_table_prototype.table, (sizeof(HTTP2_DYN_TABLE) * http2_header_table_prototype.size));
    
    if (stream_id == 0) {
        new_stream->stream_id = (c->next_stream_id++);
    } else {
        new_stream->stream_id = stream_id;
    }
    
    new_stream->header_buffer_size = 3000;
    new_stream->header_buffer = (uint8_t *)malloc(3000);
    if (!new_stream->header_buffer) {
        free(new_stream);
        return 0;
    }
    new_stream->header_buffer_len = 0;
    
    
    if (c->local_connection_settings.SETTINGS_MAX_CONCURRENT_STREAMS == HTTP2_SETTINGS_UNLIMITED) {
        streams_to_allocate = 1000;
    }
    
    if (c->streams_allocated == 0) {
        c->streams_allocated = streams_to_allocate;
        new_size = (sizeof(PHTTP2_STREAM)  * c->streams_allocated );
        c->streams = (PHTTP2_STREAM *)malloc( new_size );
        if (!c->streams) {
            c->streams_allocated = 0;
            return 0;
        }
        http2_zero(c->streams, new_size);
        c->streams[0] = new_stream;
    } else {
        for (i = 0; c->streams_allocated; i++) {
            if (c->streams[i] == 0) {
                c->streams[i] = new_stream;
                break;
            }
        }
        if (i == c->streams_allocated) {
            streams_to_allocate = 0;
            if (c->local_connection_settings.SETTINGS_MAX_CONCURRENT_STREAMS == HTTP2_SETTINGS_UNLIMITED) {
                streams_to_allocate = 1000;
            } else if (c->local_connection_settings.SETTINGS_MAX_CONCURRENT_STREAMS > c->streams_allocated) {
                streams_to_allocate = c->local_connection_settings.SETTINGS_MAX_CONCURRENT_STREAMS - c->streams_allocated;
            }
            if (streams_to_allocate > 0) {
                streams_to_allocate += c->streams_allocated;
                new_size = streams_to_allocate * sizeof(PHTTP2_STREAM);
                swap = (PHTTP2_STREAM *)malloc( new_size );
                http2_zero(swap, new_size);
                if (swap) {
                    for (i = 0, j = 0; i < c->streams_allocated; i++) {
                        if (c->streams[i]) {
                            swap[j++] = c->streams[i];
                        }
                    }
                    free(c->streams);
                    c->streams = swap;
                    c->streams_allocated = streams_to_allocate;
                } else {
                    /* Over our limit of streams */
                    free(new_stream);
                    return 0;
                }
            }
            
        }
    }
    
    return new_stream;
}

int http2_read_integer(uint8_t *pin, uint8_t prefix, size_t *read_length_out ) {
    int init_val = 0;
    int max_val = (pow(2, prefix) - 1);
    int loop = 0;
    init_val = *pin & HTTP2_IDC_MASK[8-prefix].mask;
    *read_length_out = 1;
    if (init_val < max_val) {
        return init_val;
    }
    do {
        init_val = init_val + (pin[(*read_length_out)] & 0x7F) * pow(2, loop);
        loop+=7;
    } while ( (pin[(*read_length_out)++] & 0x80) == 0x80 );
    return init_val;
}

int http2_encode_integer( uint32_t integer, uint8_t prefix, uint8_t *buff) {
    uint32_t i = integer;
    uint32_t max_val = (pow(2, prefix) - 1);
    uint8_t  existing_bits = buff[0]&HTTP2_IDC_MASK[8-prefix].reverse_mask;
    int octets_used = 0;
    if (i < max_val) {
        buff[0] = existing_bits|(uint8_t)i;
        return 1;
    }
    buff[octets_used++] = existing_bits|(uint8_t)max_val;
    i-=max_val;
    while (i > 128) {
        buff[octets_used++] = ((i%128) + 128);
        i = (int)((float)i / (float)128);
    }
    buff[octets_used++] = i;
    return octets_used;
}

/*
 * NEED to write functions that
 * decode the header values and let
 * the caller know if they should be indexed.
 * 
 * Need indexing functions and eviction functions.
 * 
 * 
 **/

/*!
 * \brief Takes a header pointer as an argument and returns the pointer to the next header.
 * 
 * \param pheader       - A pointer to the next header record.
 * 
 * \return A pointer to the NEXT header record to process, or ZERO when it's done.
 * 
 **/
uint8_t *http2_process_header( uint8_t *pheader ) {
    
}

void http2_process_headers( PHTTP2_STREAM s ) {
    size_t i = 0;
    uint8_t *pheader = s->header_buffer;
    while ( (pheader = http2_process_header(pheader)) ) {
        
    }
    
}

void http2_process_header_frame(PHTTP2_CONNECTION c, uint32_t stream_id, uint32_t flags, uint8_t *pdata, size_t length) {
    uint8_t pad_length = 0, *ppad_length = 0;
    uint32_t *pstream_dependency = 0;
    uint8_t end_headers = 0, end_stream = 0, padded = 0, priority = 0;
    uint8_t *pheader_block = 0, *header_buffer_swap = 0;
    PHTTP2_STREAM stream = 0;
    int i = 0;
    int current_offset = 0;
    int huffman_encoded = 0;
    size_t index = 0, name_len = 0, value_len = 0, badvance = 0,
            decoded_len = 0, header_bytes = 0, new_header_size = 0;
            
    if (stream_id == 0) {
        http2_error("HEADERS frame had no stream ID!\n");
        http2_connection_error(c, HTTP2_ERROR_PROTOCOL_ERROR);
        return;
    }
    
    /* Check if we already have this stream set up! */
    
    if ( c->streams > 0) {
        for (i = 0; c->streams[i]; i++) {
            if (c->streams[i]->stream_id == stream_id) {
                stream = c->streams[i];
                break;
            }
        }
    }
    if (!stream) {
        stream = http2_connection_add_stream(c, stream_id );
        stream->stream_status = HTTP2_STREAM_OPEN;
    }
    
    if ((flags & 0x1) == 0x1) end_stream = 1;
    if ((flags & 0x4) == 0x4) end_headers = 1;
    if ((flags & 0x8) == 0x8) {
        padded = 1;
    }
    if ((flags & 0x20) == 0x20) priority = 1;
    
    if (padded == 1) {
        ppad_length = &pdata[current_offset++];
        pad_length = 8 * (*ppad_length);
    }
    if (priority == 1) {
        stream->exclusive_bit = (pdata[current_offset] >> 7);
        if (stream->exclusive_bit) {
            pdata[current_offset]&=0x7F;
        }
        pstream_dependency = (uint32_t *)&pdata[current_offset];
        stream->depends_on_stream_id = ntohl(*pstream_dependency);
        
        current_offset+=4;
        stream->weight = pdata[current_offset++];
    }
    
    pheader_block = &pdata[current_offset];
    printf("HEADER\n");
    if (end_stream) printf("\t+END_STREAM\n");
    if (end_headers) printf("\t+END_HEADERS\n");
    printf("Priority? ");
    if (priority) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }
    printf("Padding length: %u bytes\n", pad_length);
    printf("Depends on stream ID: %lu\n", stream->depends_on_stream_id);
    printf("Exclusive: %u\n", stream->exclusive_bit);
    printf("Weight: %u\n", stream->weight);
    
    printf("\nHeaders:\n");
    
    
    /* Only process this if we have an END_HEADERS flag, otherwise, buffer. */
    
    i = 0;
    header_bytes = ((length-current_offset) - pad_length);
    if (header_bytes > 0) {
        if (stream->header_buffer_len + header_bytes > stream->header_buffer_size) {
            new_header_size = (stream->header_buffer_len + header_bytes + 3000);
            header_buffer_swap = (uint8_t *)malloc(new_header_size);
            if (!header_buffer_swap) {
                /* Failed to allocate new memory for header buffer */
                http2_error("Failed to allocate memory for additional headers!");
                return;
            }
            free(stream->header_buffer);
            stream->header_buffer = header_buffer_swap;
            stream->header_buffer_size = new_header_size;
        }
        memcpy(&stream->header_buffer[stream->header_buffer_len], pheader_block, header_bytes);
        stream->header_buffer_len+=header_bytes;
    }
    
    
    if (end_headers) {
        if (end_stream) {
            /* Waiting on data */
            stream->stream_status = HTTP2_STREAM_HALF_CLOSED_REMOTE;
        }
        printf("**** Maybe start preparing stuff here.  Make sure CGI processors are ready on this stream.  Whatever.  We could still have DATA frames coming, but we can get ready...");
        http2_process_headers(stream);
    }
            
    while ( i < ((length-current_offset) - pad_length)) {
        if ( (pheader_block[i] & 0x80) == 0x80 ) { /* 10000000 Indexed Header Field Representation */
            index = (size_t)http2_read_integer(&pheader_block[i], 7, &badvance);
            i+=badvance;
            printf("Indexed Header Field\n");
            if (index) {
                if (index < HTTP2_STATIC_HEADER_SIZE) {
                    printf("%s: %s\n", HTTP2_STATIC_TABLE[index].headername, HTTP2_STATIC_TABLE[index].headervalue);
                } else {
                    printf("INVALID HEADER (%zu)\n\n", index);
                }
            } else {
                printf("** ERROR, Indexed header field with ZERO for the index! ***\n");
            }
        } else if ( (pheader_block[i] & 0x40) == 0x40 ) { /* 01000000 Literal Header Field Representation */
            index = http2_read_integer(&pheader_block[i], 6, &badvance);
            printf("Literal Header Field Representation - Advancing %zu bytes.\n", badvance);
            i+=badvance;
            /* Pointer is now on a string length.  Either header name, or value. */
            if (index == 0) {
                /* Literal Header Field with Incremental Indexing -- Indexed
                 * 
                 * pointer is on header name length,
                 * 
                 **/
                printf("Literal Header Field with Incremental Indexing -- New Name\n");
                huffman_encoded = pheader_block[i] & 0x80;
                name_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance;
                /* The pointer is now of the header name string. */
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], name_len, &c->header_decode_buffer, &c->header_decode_len);
                    printf("(h) \"%s\": ", c->header_decode_buffer);
                } else {
                    printf("%.*s: ", (int)name_len, &pheader_block[i]);
                }
                i+=name_len;
                /* Move the pointer past the name */
                huffman_encoded = pheader_block[i] & 0x80;
                value_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance;
                if (value_len > 0) {
                    if (huffman_encoded) {
                        decoded_len = decompress(&pheader_block[i], value_len, &c->header_decode_buffer, &c->header_decode_len);
                        if (decoded_len > 0) {
                            printf("(h) \"%s\"\n", c->header_decode_buffer);
                        } else {
                            printf("Huffman decode failed!\n");
                        }
                    } else {
                        printf("%.*s\n", (int)value_len, &pheader_block[i]);
                    }
                } else {
                    i++;
                    printf("NO VALUE LENGTH\n");
                }
                i+=value_len;
            } else {
                /* Literal Header Field with Incremental Indexing
                 * 
                 * The pointer is at the value length that goes along with an indexed string.
                 * 
                 **/
                printf("Literal Header Field with Incremental Indexing -- Indexed Name\n");
                huffman_encoded = pheader_block[i] & 0x80;
                value_len = http2_read_integer(&pheader_block[i], 7, &badvance); /* The size in octets of the Header Value text */
                i+=badvance; /* Advance the pointer onto the VALUE string */
                
                if (index < HTTP2_STATIC_HEADER_SIZE) {
                    printf("%s: ", HTTP2_STATIC_TABLE[index].headername);
                } else {
                    printf("INVALID NAME (%zu): ", index);
                }

                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], value_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\"\n", c->header_decode_buffer);
                    } else {
                        printf("FAILED TO DECODE VALUE\n");
                    }
                } else {
                    printf("%.*s\n", (int)value_len, &pheader_block[i]);
                }
                        
                i+=value_len; /* Move past the Header Value bytes */
            }
            
            
        } else if ( (pheader_block[i] & 0xF0) == 0 ) { /* 00000000 */
            index = http2_read_integer(&pheader_block[i], 4, &badvance);
            i+=badvance;
            huffman_encoded = pheader_block[i] & 0x80;
            
            if (index == 0) {
                /* Literal Header Field without Indexing -- Indexed Name
                 * 
                 **/
                printf("Literal Header Field without Indexing -- New Name\n");
                
                name_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance;  /* Advance to the start of the string data */
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], name_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\": ", c->header_decode_buffer);
                    } else {
                        printf("** decompress() failed!!\n");
                    }
                } else {
                    printf("%.*s: ", (int)name_len, &pheader_block[i]);
                }
                i+=name_len; /* Advance the pointer past the header name */
                /* It's now at the value length */
                huffman_encoded = pheader_block[i] & 0x80;
                value_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance; /* Advance the pointer past the value_len integer to string data */
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], value_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\"\n", c->header_decode_buffer);
                    } else {
                        printf("** decompress() failed!!\n");
                    }
                } else {
                    printf("\"%.*s\"\n", (int)value_len, &pheader_block[i]);
                }
                i+=value_len; /* Move to pointer to the start of the next header info */
                
            } else {
                /* Literal Header Field without Indexing
                 * 
                 * This is a reference to the STATIC table, with a value that
                 * we're NOT adding to the dynamic table.
                 **/
                printf("Literal Header Field without Indexing -- Indexed Name\n");
                
                value_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance; /* Advance to the start of the string data */
                
                if (index < HTTP2_STATIC_HEADER_SIZE) {
                    printf("%s: ", HTTP2_STATIC_TABLE[index].headername);
                } else {
                    printf("INVALID HEADER (%zu): ", index);
                }
                
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], value_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\"\n", c->header_decode_buffer);
                    } else {
                        printf("** decompress() failed!!\n");
                    }
                } else {
                    printf("\"%.*s\"\n", (int)value_len, &pheader_block[i]);
                }
                i+=value_len;
            }
            
        } else if ((pheader_block[i] & 0x10) == 0x10) { /* 00010000 */
            index = http2_read_integer(&pheader_block[i], 4, &badvance);
            i+=badvance; /* Advance past the integer / prefix */
            huffman_encoded = pheader_block[i] & 0x80;
            
            if (index) { /* index is valid, Literal Header Field Never Indexed */
                value_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance; /* Advance to the start of the string data */
                printf("Literal Header Field Never Indexed -- Indexed Name\n");
                if (index < HTTP2_STATIC_HEADER_SIZE) {
                    printf("%s: ", HTTP2_STATIC_TABLE[index].headervalue);
                } else {
                    printf("INVALID HEADER (%zu): ", index);
                }
                
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], value_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\"\n", c->header_decode_buffer);
                    } else {
                        printf("** decompress() failed!!\n");
                    }
                } else {
                    printf("\"%.*s\"\n", (int)value_len, &pheader_block[i]);
                }
                i+=value_len;
            } else { /* index = 0, Literal Header Field Never Indexed -- Indexed Name */
                name_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance;  /* Advance to the start of the string data */
                printf("Literal Header Field Never Indexed -- New Name\n");
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], name_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\": ", c->header_decode_buffer);
                    } else {
                        printf("** decompress() failed!!\n");
                    }
                } else {
                    printf("\"%.*s\": ", (int)name_len, &pheader_block[i]);
                }
                i+=name_len; /* Advance the pointer past the header name */
                /* It's now at the value length */
                huffman_encoded = pheader_block[i] & 0x80;
                value_len = http2_read_integer(&pheader_block[i], 7, &badvance);
                i+=badvance; /* Advance the pointer past the value_len integer to string data */
                if (huffman_encoded) {
                    decoded_len = decompress(&pheader_block[i], value_len, &c->header_decode_buffer, &c->header_decode_len);
                    if (decoded_len) {
                        printf("(h) \"%s\"\n", c->header_decode_buffer);
                    } else {
                        printf("** decompress() failed!!\n");
                    }
                } else {
                    printf("\"%.*s\"\n", (int)value_len, &pheader_block[i]);
                }
                i+=value_len; /* Move to pointer to the start of the next header info */
            }
            
        } else if ((pheader_block[i] & 0x20) == 0x20) { /* 00100000 Dynamic Table Size Update */
            int dyn_tab_size_update = http2_read_integer(&pheader_block[i], 5, &badvance);
            printf("**** DYNAMIC TABLE SIZE UPDATE: %zu\n\n", dyn_tab_size_update);
            if (dyn_tab_size_update < stream->local_stream_settings.SETTINGS_HEADER_TABLE_SIZE) {
                /* Evict entries here */
                printf("\n*******************************************************\n");
                printf("*         Evict Dynamic Table Entries Here!           *\n");
                printf("*******************************************************\n\n");
            }
            stream->local_stream_settings.SETTINGS_HEADER_TABLE_SIZE = dyn_tab_size_update;
            i+=badvance;
        } else {
            i++;
        }
        
    }
    printf("\n\n");
    
    return;
}

void http2_process_stream( PHTTP2_CONNECTION c) {
    size_t          bytes_processed = 0;
    uint32_t        length = 0, *plength = 0;
    uint8_t         type = 0, *ptype = 0;
    uint8_t         flags = 0, *pflags = 0;
    uint8_t         reserved = 0, *preserved = 0;
    uint32_t        stream_id = 0, *pstream_id = 0;
    uint8_t         *ppayload = 0;
    uint8_t         *frame_out = 0;
    size_t          frame_out_size = 0;
    
    if (c->service_buffer_len < 9) {
        /* The size of the data in the buffer is less than 
         * the minimum requirements for a frame.
         */
        return;
    }
    
    printf("\nBytes to process: %zu\n", c->service_buffer_len);
    
    plength    = (uint32_t *)&c->service_buffer[0];
    ptype      =  (uint8_t *)&c->service_buffer[3];
    pflags     =  (uint8_t *)&c->service_buffer[4];
    preserved  =  (uint8_t *)&c->service_buffer[5];
    pstream_id = (uint32_t *)&c->service_buffer[5];
    
    reserved   = *preserved >> 7;
    
    if (reserved) {
        *preserved^=0x7f;
    }
    
    stream_id  = ntohl(*pstream_id);
    
    
    length      = ((ntohl(*plength) >> 8) & 0x00FFFFFF);
    type        = *ptype;
    flags       = *pflags;
    
    reserved    = (c->service_buffer[5] >> 7);
    
    if (length > 0) ppayload = (uint8_t *)&c->service_buffer[9];
        
    
    
    printf("Stream ID: %lu\n", stream_id);
    
    
    printf("\n\n***** HTTP2 FRAME ********\n");
    printf("Stream ID: %lu\n", stream_id);
    printf("     Type: ");
    switch (type) {
        case HTTP2_FRAME_CONTINUATION:
            printf("HTTP2_FRAME_CONTINUATION\n");
            break;
        case HTTP2_FRAME_DATA:
            printf("HTTP2_FRAME_DATA\n");
            break;
        case HTTP2_FRAME_GOAWAY:
            printf("HTTP2_FRAME_GOAWAY\n");
            break;
        case HTTP2_FRAME_HEADER:
            printf("HTTP2_FRAME_HEADER\n");
            /* Check the state of the stream */
            if (length > 0) {
                http2_process_header_frame(c, stream_id, flags, ppayload, length);
            }
            break;
        case HTTP2_FRAME_PING:
            printf("HTTP2_FRAME_PING\n");
            if (stream_id != 0) {
                http2_connection_error(c, HTTP2_ERROR_PROTOCOL_ERROR);
            } else if (length == 8) {
                http2_connection_error(c, HTTP2_ERROR_FRAME_SIZE_ERROR);
            } else {
                frame_out = http2_build_frame(HTTP2_FRAME_PING, 0x01, 0, 8, ppayload, &frame_out_size);
                http2_buffer_output(c, frame_out, frame_out_size);
            }
            break;
        case HTTP2_FRAME_PRIORITY:
            printf("HTTP2_FRAME_PRIORITY\n");
            break;
        case HTTP2_FRAME_PUSH_PROMISE:
            printf("HTTP2_FRAME_PUSH_PROMISE\n");
            break;
        case HTTP2_FRAME_RST_STREAM:
            printf("HTTP2_FRAME_RST_STREAM\n");
            break;
        case HTTP2_FRAME_SETTINGS:
            printf("HTTP2_FRAME_SETTINGS\n");
            if ((flags & 0x01) == 0x01) {
                http2_debug(HTTP2_VERY_IMPORTANT, "Received ACK to our SETTINGS frame.\n");
            } else {
                if (length > 0 && length%6 != 0) {
                    /* A SETTINGS frame with a length other than a multiple of 6 octets 
                     * MUST be treated as a connection error of type FRAME_SIZE_ERROR.
                     **/
                    http2_connection_error(c, HTTP2_ERROR_FRAME_SIZE_ERROR);
                } else {
                    http2_process_settings_frame( c, stream_id, ((length>0)?ppayload:0), length);
                }
            }
            
            break;
        case HTTP2_FRAME_WINDOW_UPDATE:
            printf("HTTP2_FRAME_WINDOW_UPDATE\n");
            if (length != 4) {
                http2_connection_error(c, HTTP2_ERROR_PROTOCOL_ERROR);
            } else {
                http2_process_window_update(c, stream_id, (uint32_t *)ppayload);
            }
            
            
            
            break;
        default:
            printf("UNKNOWN TYPE: 0x%x\n", type);
            break;
    }
    printf("   Length: %lu\n", length);
    printf("******************************\n\n");
    

    
    
    
    
    
    bytes_processed = 9 + length;
    printf("Removing %zu bytes from RX buffer.\n", bytes_processed);
    /* Move the processed frame off of the stack */
    memmove(c->service_buffer, &c->service_buffer[bytes_processed], (c->service_buffer_len - bytes_processed));
    c->service_buffer_len-=bytes_processed;
    
    
    
    return;
}













void http2_tcp_output_available( void ) {
    sem_post(&http2_sem_output_available);
    pthread_kill(http2_tcp_writer_thread, SIGUSR2);
}

void *http2_tcp_socket_writer( void * ) {
    size_t i = 0, j = 0;
    size_t bytes_to_write = 0, bytes_remaining = 0, ssl_bytes_written;
    int bytes_written = 0, rv = 0;
    PHTTP2_CONNECTION conn = 0;
    PHTTP2_CONNECTION connections_to_remove[100];
    PHTTP2_STREAM stream = 0;
    size_t num_connections_to_remove = 0;
    fd_set fdw;
    int highest_fd = 0;
    int srv = 0;
    struct timeval tv;
    struct sigaction sigact;
    
    huffman_zero_mem(&sigact, sizeof(struct sigaction));
    sigact.sa_handler = &http2_worker_signal_handler;
    sigaction(SIGUSR2, &sigact, NULL); /* We're using SIGUSR2 to mean that we have output to write */
    
    http2_debug(HTTP2_TCP_SOCKET_WRITER, "http2_tcp_socket_writer() alive!\n");
    while (http2_tcp_writer_die == 0) {
        sem_wait(&http2_sem_output_available); /* This will be interrupted by SIGUSR2 if there is data to send */
        http2_debug(HTTP2_TCP_SOCKET_WRITER, "There is TCP server output to send out!\n");
        num_connections_to_remove = 0;
        
        do {
            bytes_remaining = 0;
            FD_ZERO(&fdw);
            
            
            /* Build list of socket descriptors to see if they're ready to write */
            http2_lock(http2_connection_list_mtx);
            for (i = 0; i < http2_connection_list_size; i++) {
                if (!http2_connection_list[i]) continue;
                conn = http2_connection_list[i];
                if (conn->connection_is_valid == 0) {
                    if (conn->connection_id_dead == 1) {
                        connections_to_remove[num_connections_to_remove++] = conn;
                    }
                    continue;
                }
                http2_lock(conn->output_buffer_mutex);
                if (conn->output_len > 0) {
                    if (conn->socket > highest_fd) {
                        highest_fd = conn->socket;
                    }
                    FD_SET(conn->socket, &fdw);
                }
                http2_unlock(conn->output_buffer_mutex);
                
            }
            http2_unlock(http2_connection_list_mtx);
            
            
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            srv = select( (highest_fd + 1), 0, &fdw, 0, &tv); /* A signal will interrupt this and we can start our loop over */
            
            if (srv) {
                http2_lock(http2_connection_list_mtx);
                for (i = 0; i < http2_connection_list_size; i++) {
                    if (!http2_connection_list[i]) continue;
                    conn = http2_connection_list[i];
                    if (FD_ISSET(conn->socket, &fdw)) {
                        http2_lock(conn->output_buffer_mutex);
                        bytes_to_write = ((conn->output_len > 0xFFFF)?0xFFFF:conn->output_len);
                        if (conn->ssl) {
                            rv = SSL_write_ex(conn->ssl, conn->output_buffer, bytes_to_write, &ssl_bytes_written);
                            if (rv > 0) {
                                http2_debug(HTTP2_TCP_SOCKET_WRITER, "TLS >> Wrote %zu bytes of data.\n", ssl_bytes_written);
                                /* Move the data in this buffer forward */
                                memmove(conn->output_buffer, &conn->output_buffer[ssl_bytes_written], (conn->output_len-ssl_bytes_written));
                                conn->output_len-=ssl_bytes_written;
                                bytes_remaining += (bytes_to_write - ssl_bytes_written);
                                http2_debug(HTTP2_TCP_SOCKET_WRITER, "Bytes available to write: %zu\n", bytes_remaining);
                            } else {
                                switch (SSL_get_error(conn->ssl, rv)) {
                                    case SSL_ERROR_WANT_WRITE:
                                        bytes_remaining+=bytes_to_write;
                                        break;
                                    default:
                                        conn->connection_is_valid = 0;
                                        break;
                                }
                            }
                        } else {
                            bytes_written = send(conn->socket, conn->output_buffer, bytes_to_write, MSG_NOSIGNAL);
                            if (bytes_written == -1) {
                                if (errno == EBADF || 
                                    errno == ECONNRESET || 
                                    errno == EDESTADDRREQ || 
                                    errno == EFAULT || 
                                    errno == EMSGSIZE || 
                                    errno == ENOBUFS || 
                                    errno == ENOMEM || 
                                    errno == ENOTCONN || 
                                    errno == ENOTSOCK || 
                                    errno == EPIPE) 
                                {
                                    conn->connection_is_valid = 0;
                                }
                            } else {
                                /* Move the data in this buffer forward */
                                if (bytes_written > 0) {
                                    http2_debug(HTTP2_TCP_SOCKET_WRITER, "TCP >> Wrote %u bytes of data.\n", bytes_written);
                                    memmove(conn->output_buffer, &conn->output_buffer[bytes_written], (conn->output_len-(size_t)bytes_written));
                                    conn->output_len-=bytes_written;
                                }
                                bytes_remaining += (bytes_to_write - (size_t)bytes_written);
                            }
                        }
                        http2_unlock(conn->output_buffer_mutex);
                    }
                }
                http2_unlock(http2_connection_list_mtx);
            }
            
            
            
        } while (bytes_remaining > 0);
        
        /* Remove any connections from monitoring that we need to */
        if (num_connections_to_remove > 0) {
            http2_lock(http2_connection_list_mtx);
            for (j = 0; j < num_connections_to_remove; j++) {
                for (i = 0; i < http2_connection_list_size; i++) {
                    if (http2_connection_list[i] == 0) continue;
                    if (connections_to_remove[j] == http2_connection_list[i]) {
                        http2_debug(HTTP2_TCP_SOCKET_WRITER, "Removing a TCP/TLS connection from monitoring and freeing its HTTP2_CONNECTION structure!\n");
                        /* Free everything allocated for this connection */
                        if (http2_connection_list[i]->output_buffer) {
                            free(http2_connection_list[i]->output_buffer);
                        }
                        if (http2_connection_list[i]->streams) {
                            int k = 0, l = 0;
                            /* Free stream-related stuff here! */
                            for (k = 0; k < http2_connection_list[i]->streams_allocated; k++) {
                                stream = http2_connection_list[i]->streams[k];
                                for (l = http2_header_table_prototype.used; 
                                        l < stream->decoding_table.size; 
                                        l++) 
                                {
                                    free(stream->decoding_table.table[l].name.ptr);
                                    free(stream->decoding_table.table[l].value.ptr);
                                }
                                free(stream->decoding_table.table);
                                if (http2_connection_list[i]->streams[k]->header_buffer) {
                                    free(http2_connection_list[i]->streams[k]->header_buffer);
                                }
                                free(http2_connection_list[i]->streams[k]);
                                http2_connection_list[i]->streams[k] = 0;
                            }
                            free(http2_connection_list[i]->streams);
                        }
                        http2_free_mutex(http2_connection_list[i]->output_buffer_mutex);
                        if (http2_connection_list[i]->service_buffer) {
                            free(http2_connection_list[i]->service_buffer);
                        }
                        free(http2_connection_list[i]);
                        http2_connection_list[i] = 0;
                        break;
                    }
                }
            }
            http2_unlock(http2_connection_list_mtx);
            num_connections_to_remove = 0;
        }
        
    }
    http2_debug((HTTP2_TCP_SOCKET_WRITER|HTTP2_VERY_IMPORTANT), "TCP socket writer shutting down now.\n");
    return 0;
}


int http2_init( void ) {
    int i;
    size_t n = 0;
    PHTTP2_DYN_TABLE t = 0;
    PHTTP2_CONNECTION_THREAD_CONTROL thread;
    
    if (http2_library_initialized) {
        http2_debug(HTTP2_INIT|HTTP2_VERY_IMPORTANT, "http2_init() already called successfully.\n");
        return HTTP2_SUCCESS;
    }
    
    if (HTTP2_MODULE_SETTINGS.initial_connection_threads == 0 || 
            ((HTTP2_MODULE_SETTINGS.initial_connection_threads > HTTP2_MODULE_SETTINGS.max_connection_threads) &&
            HTTP2_MODULE_SETTINGS.max_connection_threads != HTTP2_SETTINGS_UNLIMITED)) 
    {
        /* We cannot start without an initial thread count...
         * the default was 10, so someone screwed up somewhere..
         * 
         * Or, someone set the MAX thread count as fewer than the initial count...
         * 
         */
        http2_error("initial_connection_threads==%d and max_connection_threads==%d\n",
                HTTP2_MODULE_SETTINGS.initial_connection_threads,
                HTTP2_MODULE_SETTINGS.max_connection_threads);
        return HTTP2_ERROR_INVALID_INITIAL_THREAD_COUNT;
        
    }
    
    if (HTTP2_MODULE_SETTINGS.max_connection_backlog <= 0) {
        http2_error("HTTP2_MODULE_SETTINGS.max_connection_backlog == %d !\n", HTTP2_MODULE_SETTINGS.max_connection_backlog);
        return HTTP2_ERROR_INVALID_BACKLOG_COUNT;
    }
    
    /* Create the backlog queue */
    http2_debug(HTTP2_INIT, "Allocating %d spaces (%zu bytes) for connection backlog.\n", HTTP2_MODULE_SETTINGS.max_connection_backlog, ((sizeof(PHTTP2_CONNECTION) * HTTP2_MODULE_SETTINGS.max_connection_backlog)));
    http2_connection_backlog_queue = (PHTTP2_CONNECTION *)malloc( (sizeof(PHTTP2_CONNECTION) * HTTP2_MODULE_SETTINGS.max_connection_backlog));
    if (!http2_connection_backlog_queue) {
        http2_error("Failed to allocate http2_connection_backlog_queue!\n");
        return HTTP2_ERROR_NO_MEMORY;
    }
    
    http2_connection_list_size = 100;
    http2_connection_list = (PHTTP2_CONNECTION *)malloc( (sizeof(PHTTP2_CONNECTION) * http2_connection_list_size));
    if (!http2_connection_list) {
        free(http2_connection_backlog_queue);
        http2_connection_backlog_queue = 0;
        http2_connection_list_size = 0;
        http2_error("Failed to allocate http2_connection_list!\n");
        return HTTP2_ERROR_NO_MEMORY;
    }
    
    /* Zero out connection list */
    huffman_zero_mem(http2_connection_list, (sizeof(PHTTP2_CONNECTION) * http2_connection_list_size));
    
    http2_connection_list_mtx = http2_new_mutex(0);
    if (!http2_connection_list_mtx) {
        http2_error("Failed to set up the connection list's mutex!\n");
        free(http2_connection_list);
        http2_connection_list = 0;
        http2_connection_list_size = 0;
        free(http2_connection_backlog_queue);
        http2_connection_backlog_queue = 0;
        return HTTP2_ERROR_MUTEX_FAILED;
    }
    
    
    
    if (sem_init(&http2_sem_output_available, 0, 0) == -1) {
        http2_error("sem_init() failed trying to set up 'http2_sem_output_available'!\n");
        free(http2_connection_list);
        http2_connection_list = 0;
        http2_connection_list_size = 0;
        
        http2_free_mutex(http2_connection_list_mtx);
        http2_connection_list_mtx = 0;
        free(http2_connection_backlog_queue);
        http2_connection_backlog_queue = 0;
        return HTTP2_ERROR_MUTEX_FAILED;
    }
    
    
    /* Initialize (clear out) the connection queue buffer */
    huffman_zero_mem(http2_connection_backlog_queue, (sizeof(PHTTP2_CONNECTION) * HTTP2_MODULE_SETTINGS.max_connection_backlog));

    
    if (pthread_create(&http2_tcp_writer_thread, 0, &http2_tcp_socket_writer, 0)) {
        /* Free all resources allocated here! */
        http2_error("Failed to create TCP/TLS writer thread! ** We need to free all resources set up before here in http2_init()... I got lazy.\n");
        return HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL;
    }
    
    
    /* Create the mutex that protects the http2_connection_backlog_queue */
    if ( (http2_connection_backlog_mutex = http2_new_mutex(0)) == HTTP2_INVALID_MUTEX  ) {
        http2_error("Failed to create http2_connection_backlog_mutex\n");
        free(http2_connection_backlog_queue);
        http2_connection_backlog_queue = 0;
        return HTTP2_ERROR_MUTEX_FAILED;
    }
    
    
    if (HTTP2_MODULE_SETTINGS.max_connection_threads == HTTP2_SETTINGS_UNLIMITED) {
        http2_connection_thread_list_size = 100;
    } else {
        http2_connection_thread_list_size = HTTP2_MODULE_SETTINGS.max_connection_threads;
    }
    
    
    /* Allocate list to hold HTTP2_CONNECTION_THREAD_POINTERS */
    http2_connection_thread_list = 
            (PHTTP2_CONNECTION_THREAD_CONTROL *)malloc( sizeof(PHTTP2_CONNECTION_THREAD_CONTROL) * http2_connection_thread_list_size );
    if (!http2_connection_thread_list) {
        http2_error("Failed to allocate memory for http2_connection_thread_list!\n");
        
        http2_debug(HTTP2_INIT, "Freeing http2_connection_backlog_queue\n");
        free(http2_connection_backlog_queue);
        http2_connection_backlog_queue = 0;
        
        http2_debug(HTTP2_INIT, "http2_free_mutex(http2_connection_backlog_mutex)\n");
        http2_free_mutex(http2_connection_backlog_mutex);
        http2_connection_backlog_mutex = 0;
        return HTTP2_ERROR_NO_MEMORY;
    }
    
    huffman_zero_mem(http2_connection_thread_list, sizeof(PHTTP2_CONNECTION_THREAD_CONTROL) * http2_connection_thread_list_size);
    
    
    http2_debug(HTTP2_INIT, "Creating 'http2_active_worker_mutex'\n");
    http2_active_worker_mutex = http2_new_mutex(1);
    if ( http2_active_worker_mutex == HTTP2_INVALID_MUTEX ) {
        http2_error("Failed to create new locked mutex http2_active_worker_mutex!\n");
        free(http2_connection_thread_list);
        free(http2_connection_backlog_queue);
        http2_free_mutex(http2_connection_backlog_mutex);
        return HTTP2_ERROR_MUTEX_FAILED;
    }
    
    http2_header_table_prototype.table = (PHTTP2_DYN_TABLE)malloc( (sizeof(HTTP2_DYN_TABLE) * http2_header_table_prototype.size) );
    if (!http2_header_table_prototype.table) {
        http2_error("Failed to create new prototype decoding table!\n");
        free(http2_connection_thread_list);
        free(http2_connection_backlog_queue);
        http2_free_mutex(http2_connection_backlog_mutex);
        return HTTP2_ERROR_NO_MEMORY;
    }
    
    http2_zero(http2_header_table_prototype.table, (sizeof(HTTP2_DYN_TABLE) * http2_header_table_prototype.size));
    for (i = 0; i < http2_header_table_prototype.size; i++) {
        t = &http2_header_table_prototype.table[i];
        if (i < HTTP2_STATIC_HEADER_SIZE) {
            t->name.len = strlen(HTTP2_STATIC_TABLE[i].headername);
            t->name.size = t->name.len;
            t->name.ptr = (char *)HTTP2_STATIC_TABLE[i].headername;
            t->value.len = strlen(HTTP2_STATIC_TABLE[i].headervalue);
            t->value.size = t->name.len;
            t->value.ptr = (char *)HTTP2_STATIC_TABLE[i].headervalue;
        } else {
            t->name.size = 250;
            t->name.len  = 0;
            t->name.ptr = (char *)malloc(250);
            t->value.size = 1200;
            t->value.len  = 0;
            t->value.ptr = (char *)malloc(1200);
        }
    }
    
    
    
    http2_debug(HTTP2_INIT, "Creating worker threads.\n");
    /* Create the initial worker thread pool */
    for (i = 0; i < HTTP2_MODULE_SETTINGS.initial_connection_threads; i++) {
        http2_debug(HTTP2_INIT, "Creating thread %d out of %d\n", (i+1), HTTP2_MODULE_SETTINGS.initial_connection_threads);
        if ((thread = create_http2_connection_thread()) == HTTP2_ERROR_MAX_WORKER_THREADS) {
            /* Free all threads we've created */
            http2_debug(HTTP2_INIT, "A thread failed to start.  Shutting down all threads we've started!\n");
            for (i=(i-1); i >=0; i--) {
                retire_http2_connection_thread(thread);
            }
            free(http2_connection_thread_list);
            free(http2_connection_backlog_queue);
            http2_free_mutex(http2_connection_backlog_mutex);
            http2_free_mutex(http2_active_worker_mutex);
            return HTTP2_ERROR_FAILED_TO_CREATE_THREAD_POOL;
        }
    }
    http2_debug(HTTP2_INIT, "Worker threads created. Unlocking mutex.\n");
    http2_unlock(http2_active_worker_mutex);
    http2_debug(HTTP2_INIT, "Mutex unlocked\n");
    
    /* This allocates space for the static table, and a dynamic table
     * of the same size as the static table.
     */
    
    
    
    
    http2_library_initialized = 1;
    return HTTP2_SUCCESS;
}

PHTTP2_CONNECTION_THREAD_CONTROL
                create_http2_connection_thread( void ) {
    PHTTP2_CONNECTION_THREAD_CONTROL thread = 0;
    PHTTP2_CONNECTION_THREAD_CONTROL *swap = 0;
    int r = 0;
    
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Locking active worker mutex.\n");
    if (http2_lock(http2_active_worker_mutex) < HTTP2_SUCCESS) {
        http2_error("Failed to lock mutex.\n");
        return HTTP2_ERROR_MAX_WORKER_THREADS;
    }
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Mutex locked.\n");
    
    /* Check if we can create new worker threads or not */
    if (HTTP2_MODULE_SETTINGS.max_connection_threads == HTTP2_SETTINGS_UNLIMITED) {
        if ( http2_active_worker_threads == http2_connection_thread_list_size ) {
            http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Adding more threads.  max_connection_threads is set to HTTP2_SETTINGS_UNLIMITED, and we've reached that limit!\n");
            swap = (PHTTP2_CONNECTION_THREAD_CONTROL *)malloc( sizeof(PHTTP2_CONNECTION_THREAD_CONTROL) * (http2_connection_thread_list_size + 100));
            if (!swap) {
                http2_error("Failed to allocate 100 more spaces in the http2_connection_thread_list\n");
                http2_unlock(http2_active_worker_mutex);
                return HTTP2_ERROR_MAX_WORKER_THREADS;
            }
            http2_connection_thread_list_size+=100;
            http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Zeroing memory.\n");
            huffman_zero_mem(swap, sizeof(PHTTP2_CONNECTION_THREAD_CONTROL) * (http2_connection_thread_list_size + 100));
            http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Copying memory.\n");
            memcpy(swap, http2_connection_thread_list, sizeof(PHTTP2_CONNECTION_THREAD_CONTROL) * http2_active_worker_threads);
            http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Freeing old memory.\n");
            free(http2_connection_thread_list);
            http2_connection_thread_list = swap;
        }
    } else {
        if (http2_active_worker_threads == HTTP2_MODULE_SETTINGS.max_connection_threads) {
            http2_unlock(http2_active_worker_mutex);
            return HTTP2_ERROR_MAX_WORKER_THREADS;
        }
    }
    
    
    
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Setting up new thread control struct.\n");
    thread = (PHTTP2_CONNECTION_THREAD_CONTROL)malloc(sizeof(HTTP2_CONNECTION_THREAD_CONTROL));
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Zeroing new thread control struct.\n");
    huffman_zero_mem(thread, sizeof(HTTP2_CONNECTION_THREAD_CONTROL));
    
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Initializing semaphore\n");
    if (sem_init(&thread->new_job, 0, 0)) {
        /* Failed to initialize the semaphore */
        http2_error("Failed to create semaphore.\n");
        http2_unlock(http2_active_worker_mutex);
        free(thread);
        return HTTP2_ERROR_MAX_WORKER_THREADS;
    }
    
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Semaphore created.\n");
    
    if (pthread_create(&thread->thread, 0, &http2_connection_thread, (void *)thread)) {
        /* Failed to create thread */
        http2_error("FAILED TO START THREAD!\n");
        http2_unlock(http2_active_worker_mutex);
        free(thread);
        return HTTP2_ERROR_MAX_WORKER_THREADS;
    }
    
    http2_debug(CREATE_HTTP2_CONNECTION_THREAD, "Waiting on confirmation of thread running...\n");
    /* Wait up to 1s for the thread to initialize and launch */
    HTTP2_WAIT( (thread->status & HTTP2_THREAD_ACTIVE == HTTP2_THREAD_ACTIVE), 1000  ) {
        if (http2_active_worker_threads < HTTP2_MODULE_SETTINGS.initial_connection_threads) {
            thread->is_fundamental = 1;
        }
        http2_connection_thread_list[http2_active_worker_threads++] = thread;
        http2_unlock(http2_active_worker_mutex);
        http2_debug((CREATE_HTTP2_CONNECTION_THREAD), "Worker thread successfully launched!\n");
        return thread;
    } else {
        /* The thread didn't start in a timely manner */
        http2_error("Failed to start thread!\n");
        thread->status|=HTTP2_THREAD_DIE;
        sem_post(&thread->new_job);
        http2_unlock(http2_active_worker_mutex);
        return HTTP2_ERROR_MAX_WORKER_THREADS;
    }
    
    
    
    
}


int retire_http2_connection_thread( PHTTP2_CONNECTION_THREAD_CONTROL control ) {
    size_t i = 0;
    
    http2_lock(http2_active_worker_mutex);
    
    /* Find this thread in the list */
    
    for (; i < http2_active_worker_threads; i++) {
        
        if (http2_connection_thread_list[i] == control) {
            control->status|=HTTP2_THREAD_DIE_AND_JOIN;
            sem_post(&control->new_job);
            pthread_kill(control->thread, SIGUSR2);
            HTTP2_WAIT( control->status&HTTP2_THREAD_DEAD==HTTP2_THREAD_DEAD, 500 ) {
                pthread_join(control->thread, 0);
                sem_destroy(&control->new_job);
                http2_remove_thread_from_list(control);
                free(control);
                http2_unlock(http2_active_worker_mutex);
                return HTTP2_SUCCESS;
            } else {
                control->status^= HTTP2_THREAD_JOIN;
            }
        }
    }
    
    if (i == http2_active_worker_threads) {
        http2_unlock(http2_active_worker_mutex);
        return HTTP2_ERROR_WORKER_NOT_FOUND;
    }
    http2_unlock(http2_active_worker_mutex);
    return HTTP2_OK;
}


int schedule_http2_connection_destruction( PHTTP2_CONNECTION_THREAD_CONTROL control ) {
    if (control) control->status|=HTTP2_THREAD_DIE;
}


/* WORKING ON THIS !!! */
void http2_shutdown_all( void ) {
    PHTTP2_CONNECTION_THREAD_CONTROL control;
    http2_lock(http2_active_worker_mutex);
    size_t i = 0;
    
    http2_debug(HTTP2_SHUTDOWN_ALL, "Shutting down all HTTP2 worker thread!\n");
    
    /* Find this thread in the list */
    for (; i < http2_active_worker_threads; i++) {
        control = http2_connection_thread_list[i];
        control->status|=HTTP2_THREAD_DIE;
        sem_post(&control->new_job);
    }
    http2_unlock(http2_active_worker_mutex);
    
    HTTP2_WAIT( (http2_active_worker_threads == 0), 10000) {
        http2_debug(HTTP2_SHUTDOWN_ALL, "Yay! All worker threads shut down like they're supposed to!\n\n");
    } else {
        http2_debug(HTTP2_SHUTDOWN_ALL, "*** PROBLEM: All the threads didn't shut themselves down! There are %d workers left working!\n\n");
    }
    
    return;
}


void http2_get_default_connection_settings( struct _http2_settings *s ) {
    memcpy(s, &http2_settings, sizeof(struct _http2_settings));
}

int delegate_new_connection( PHTTP2_CONNECTION c ) {
    PHTTP2_CONNECTION_THREAD_CONTROL thread = 0;
    PHTTP2_CONNECTION *swap = 0;
    size_t i = 0, swap_size = 0;
    int r = HTTP2_SUCCESS;
    

    /* Set up the default HTTP2_CONNECTION settings for this new connection */
    http2_get_default_connection_settings(&c->local_connection_settings);    
    http2_get_default_connection_settings(&c->remote_connection_settings);    
    
    /* Get everything set up so this connection has a fighting chance */
    c->next_stream_id = 1;
    c->connection_start_time = time(0);
    c->connection_is_valid = 1;
    c->connection_last_operation = time(0);
    c->creator = pthread_self();
    
    c->output_buffer_mutex = http2_new_mutex(0);
    if (!c->output_buffer_mutex) {
        return HTTP2_ERROR_MUTEX_FAILED;
    }
    
    c->output_buffer = (uint8_t *)malloc(130000);
    if (c->output_buffer) {
        c->output_buffer_size = 130000;
        c->output_len = 0;
    } else {
        http2_free_mutex(c->output_buffer_mutex);
        return HTTP2_ERROR_NO_MEMORY;
    }
    
    c->header_decode_len = 1500;
    
    c->header_decode_buffer = (char *)malloc(c->header_decode_len);
    if (!c->header_decode_buffer) {
        c->header_decode_len = 0;
        return HTTP2_ERROR_NO_MEMORY;
        
    }
    
    /* Add this new connection to the output-processing threads' queues 
     * to watch for output.
     */
    http2_lock(http2_connection_list_mtx);
    
    for (i = 0; i < http2_connection_list_size; i++) {
        if (http2_connection_list[i] == 0) {
            break;
        }
    }
    
    if (i == http2_connection_list_size) {
        swap_size = (http2_connection_list_size + 100);
        swap = (PHTTP2_CONNECTION *)malloc(swap_size);
        if (!swap) {
            http2_unlock(http2_connection_list_mtx);
            return HTTP2_ERROR_NO_MEMORY;
        }
        huffman_zero_mem(swap, swap_size);
        memcpy(swap, http2_connection_list, (sizeof(PHTTP2_CONNECTION *) * http2_connection_list_size));
        free(http2_connection_list);
        http2_connection_list = swap;
        http2_connection_list_size = swap_size;
    }
    http2_connection_list[i] = c;
    http2_unlock(http2_connection_list_mtx);
    
    
    /* Pass a connection to a waiting service worker thread */
    http2_lock(http2_active_worker_mutex);
    
    for (; i < http2_active_worker_threads; i++) {
        thread = http2_connection_thread_list[i];
        if (thread->available && thread->connection == 0) {
            http2_debug(DELEGATE_NEW_CONNECTION, "Found available thread #%zu\n", i);
            thread->connection = c;
            sem_post(&thread->new_job);
            HTTP2_WAIT( thread->connection == 0, 100 ) {
                http2_debug(DELEGATE_NEW_CONNECTION, "Assigned new connection to thread #%zu\n", i);
                break;
            } else {
                /* We failed to assign a connection to a thread that said it was 
                 * ready.  This is a problem.  We need to tell this thread to die.
                 */
                http2_error("Thread #%zu failed to accept the job in a timely manner.  Telling it to die and looking for another worker.", i);
                thread->status = HTTP2_THREAD_DIE;
                http2_remove_thread_from_list(thread);
            }
        }
    }
    http2_unlock(http2_active_worker_mutex);
    
    
    
    
    
    
    if (i == http2_active_worker_threads) { /* If we didn't find a worker thread to accept the connection */
        http2_debug(DELEGATE_NEW_CONNECTION|HTTP2_VERY_IMPORTANT,"Failed to find an available worked thread! Attempting to push connection onto backlog queue!\n");
        r = http2_push_connection(c);
    }
    return r;
}

int http2_remove_thread_from_list( PHTTP2_CONNECTION_THREAD_CONTROL thread ) {
    size_t i = 0, j = 0;
    http2_debug(HTTP2_REMOVE_THREAD_FROM_LIST, "Locking mutex...\n");
    int r = http2_lock(http2_active_worker_mutex);
    if (r < HTTP2_SUCCESS) {
        http2_debug(HTTP2_REMOVE_THREAD_FROM_LIST, "Failed to lock mutex returning...\n");
        return r;
    }
    http2_debug(HTTP2_REMOVE_THREAD_FROM_LIST, "Searching for thread in the list...\n");
    for (; i < http2_active_worker_threads; i++) {
        if (thread == http2_connection_thread_list[i]) {
            http2_debug(HTTP2_REMOVE_THREAD_FROM_LIST, "Removing thread from the list...\n");
            http2_connection_thread_list[i] = 0;
            for (j = (i+1); j < http2_active_worker_threads; j++) {
                http2_connection_thread_list[i++] = 
                        http2_connection_thread_list[j];
            }
            http2_active_worker_threads--;
            http2_debug(HTTP2_REMOVE_THREAD_FROM_LIST, "Done resorting the list...\n");
            break;
        }
    }
    http2_debug(HTTP2_REMOVE_THREAD_FROM_LIST, "Unlocking mutex and exiting...\n");
    http2_debug(HTTP2_VERY_IMPORTANT, "There are %d active workers remaining...\n", http2_active_worker_threads);
    return http2_unlock(http2_active_worker_mutex);
}


void http2_worker_signal_handler( int signum ) {
    return;
}


void *http2_connection_thread( void *p ) {
    // v--- Clipboard copy/debug purposes ---v
    
    // http2_debug(HTTP2_CONNECTION_THREAD, "\n");
    
    size_t it = 0;
    int rv = 0, i = 0, recv_bytes_read = 0;
    PHTTP2_CONNECTION_THREAD_CONTROL control =
            (PHTTP2_CONNECTION_THREAD_CONTROL)p;
    PHTTP2_CONNECTION current_connection;
    struct sigaction sigact;

    /*** REMOVE ANY TEMP VARS HERE!!! ****/
    char *_x_buffers = 0;
    /*****************************************/
    
    if (!control) {
        pthread_detach(pthread_self());
        return 0;
    }
    
    /* Do any additional set up from here **********************************/
    
    /* Catch these signals on a thread level, basically so they'll 
     * interrupt any blocking operations.
     */
    huffman_zero_mem(&sigact, sizeof(struct sigaction));
    sigact.sa_handler = &http2_worker_signal_handler;
    sigaction(SIGUSR1, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL); /* Used to interrupt a wait operation */
    sigaction(SIGPIPE, &sigact, NULL); /* Nothing, maybe use to get recv() moving or something */
    
    
    /* to here *************************************************************/
    
    http2_debug(HTTP2_CONNECTION_THREAD,"Marking thread as active\n");
    control->status|=HTTP2_THREAD_ACTIVE;
    http2_debug(HTTP2_CONNECTION_THREAD, "Thread started and listening...\n");
    while ( (control->status & HTTP2_THREAD_DIE ) != HTTP2_THREAD_DIE ) {
        
        control->available = 1;
        http2_debug(HTTP2_CONNECTION_THREAD,"Thread waiting on semaphore\n");
        sem_wait(&control->new_job);
        http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "*** SEMAPHORE SIGNALLED ***\n");
        control->available = 0;
        
        current_connection = control->connection;
        
        if (current_connection) {
            control->connection = 0;
            
            /* Set up our IO buffers */
            
            current_connection->service_buffer_size = (65535*2);
            current_connection->service_buffer = (char *)malloc(current_connection->service_buffer_size);

            if (!current_connection->service_buffer) {
                control->status = HTTP2_THREAD_DIE;
            }
            
            
            /* Handle new connection here */
            /* If our HTTP2_THREAD_DIE bit is set, wrap it up. */
            
            if (current_connection->ssl) {
                if (!ssl_accept(current_connection->ssl)) {
                    http2_error("Failed to complete TLS handshake on new connection.");
                    SSL_shutdown(current_connection->ssl);
                    SSL_free(current_connection->ssl);
                    shutdown(current_connection->socket, 2);
                    closesocket(current_connection->socket);

                    if (current_connection->service_buffer) {
                        free(current_connection->service_buffer);
                        current_connection->service_buffer = 0;
                    }
                    continue;
                }
                http2_debug(HTTP2_CONNECTION_THREAD, "TLS Handshake complete.  Entering service loop.\n");
            }
            set_socket_blocking_state(current_connection->socket, 1);
            
            /* Connection service loop */
            while ( ((control->status & HTTP2_THREAD_DIE ) != HTTP2_THREAD_DIE) &&
                    current_connection->connection_is_valid &&
                    ((time(0) - current_connection->connection_last_operation) < HTTP2_MODULE_SETTINGS.connection_timeout))
            {
                FD_ZERO(&current_connection->fdr);
                FD_SET(current_connection->socket, &current_connection->fdr);
                current_connection->tv.tv_sec = 2;
                current_connection->tv.tv_usec == 0;
                rv = select( (current_connection->socket + 1), &current_connection->fdr, 0, 0, &current_connection->tv );
                if (rv > 0) {
                    recv_bytes_read = 0;
                    current_connection->bytes_read = 0;
                    
                    /* Remember, only use OpenSSL here, if we know it is a TLS connection!  Otherwise, just read 
                     * from the socket!
                     */
                    
                    if (current_connection->ssl) {
                        /* Data available. See if SSL_read() can decipher it yet. */
                        printf("\nSSL_read_ex()\n");
                        rv = SSL_read_ex(current_connection->ssl, current_connection->read_buffer, 65535, &current_connection->bytes_read);
                        printf("\nSSL_read_ex() DONE\n");
                        if (rv <= 0 ) {
                            if ( (SSL_get_error(current_connection->ssl, rv)) != SSL_ERROR_WANT_READ ) {
                                current_connection->connection_is_valid = 0;
                                break;
                            } else {
                                /* We got SSL_ERROR_WANT_READ */
                                continue; /* Back to top to read more.  We don't want to cast 
                                           * current_connection->bytes_read to recv_bytes_read as an int 
                                           * because it was zero; our connection is still valid.
                                           **/
                            }
                        }
                        recv_bytes_read = (int)current_connection->bytes_read;
                    } else {
                        /* Read non-TLS data here! */
                        printf("\nrecv()\n");
                        recv_bytes_read = recv(current_connection->socket, current_connection->read_buffer, 0xFFFF, 0);
                        printf("\nrecv() DONE\n");
                    }

                    
                    if (recv_bytes_read > 0) {
                        /* We have data read for the socket, or from OpenSSL */
                        if ( (current_connection->service_buffer_len + recv_bytes_read) > current_connection->service_buffer_size ) {
                            current_connection->swap_len = (current_connection->service_buffer_size + (recv_bytes_read + 65535));
                            current_connection->swap = (char *)realloc(current_connection->service_buffer, current_connection->swap_len);
                            if (!current_connection->swap) {
                                http2_error("Failed to increase buffer size from %zu bytes to %zu bytes to accomodate new inbound TLS data!  Closing this connection!\n", 
                                        current_connection->service_buffer_size, 
                                        current_connection->swap_len);
                                current_connection->connection_is_valid = 0;
                                break;
                            }
                            free(current_connection->service_buffer);
                            current_connection->service_buffer = current_connection->swap;
                            current_connection->service_buffer_size = current_connection->swap_len;
                        }
                        memcpy(&current_connection->service_buffer[current_connection->service_buffer_len], 
                                current_connection->read_buffer, 
                                (size_t)recv_bytes_read);


                        current_connection->service_buffer_len+=(size_t)recv_bytes_read;
                    } else if (recv_bytes_read < 0) { /* Shouldn't be here with OpenSSL */
                        if (current_connection->ssl) {
                            http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "*** We should NEVER be here!  SSL_read_ex() should never return a NEGATIVE bytes read!\n");
                        }
                        if (errno == EBADF ||
                            errno == EFAULT ||
                            errno == EINVAL ||
                            errno == ENOMEM ||
                            errno == ENOTCONN ||
                            errno == ENOTSOCK)
                        {
                            current_connection->connection_is_valid = 0;
                            break;
                        }
                    } else {
                        /* Only way we're here is if there was a TCP socket shutdown by the client.  We should NEVER be here 
                         * if this is a TLS connection!
                         */
                        current_connection->connection_is_valid = 0;
                        break;
                    }
                } else if (rv == 0) {
                    printf("\n\n*** Timeout with no data ***\n\n");
                } else {
                    if (errno == EBADF || errno == ENOMEM ) {
                        current_connection->connection_is_valid = 0;
                        break;
                    } else if (errno == EINTR) {
                        /* We probably caught a signal meaning that we have data to write */
                        http2_error("EINTR signal caught!!\n");
                        current_connection->connection_is_valid = 0;
                    }
                    
                }
                
                
                if (current_connection->phttp) {
                    if (current_connection->phttp->is_processing()) {
                        http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "Another request came in before we've finished processing the first! Discarding it.\n\n");
                        http2_buffer_evict_octets(current_connection, current_connection->service_buffer_len);
                    } else {
                        http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "Another request part came in but we're waiting for more data.\n\n");
                    }
                }
                
                /* If we haven't yet, determine what version of HTTP we're expecting. */
                
                
                /* Go throught all active HTTP connections and see if any are ready to be served! */
                
                
                if (current_connection->protocol_identified == 0) {
                    /* Check for HTTP/3 */
                    /* Check for HTTP/2 */
                    if (!current_connection->protocol_identified) {
                        if (current_connection->service_buffer_len >= HTTP2_CLIENT_PREFACE_LEN) {
                            if (!strncmp((const char *)current_connection->service_buffer, HTTP2_CLIENT_PREFACE, HTTP2_CLIENT_PREFACE_LEN)) {
                                current_connection->protocol_id = HTTP2_0;
                                current_connection->protocol_identified = 1;
                                http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "Calling http2_connection_send_settings()\n");
                                /* Remove the HTTP2 preface here! */
                                if (current_connection->service_buffer_len > HTTP2_CLIENT_PREFACE_LEN) {
                                    memmove(current_connection->service_buffer, 
                                            &current_connection->service_buffer[HTTP2_CLIENT_PREFACE_LEN],
                                            current_connection->service_buffer_len - HTTP2_CLIENT_PREFACE_LEN);
                                    current_connection->service_buffer_len-=HTTP2_CLIENT_PREFACE_LEN;
                                } else {
                                    current_connection->service_buffer_len = 0;
                                }
                                http2_connection_send_settings(current_connection);
                                
                            }
                        }
                    }
                    /* Check for HTTP/1.2 */
                    if (!current_connection->protocol_identified) {
                        for (i = 0; i < HTTP_PROTOCOL_VERSION_COUNT; i++) {
                            if (current_connection->service_buffer_len >= strlen(PROTOCOL_VERSION[i].on_wire)) {
                                if (strstr((const char *)current_connection->service_buffer, PROTOCOL_VERSION[i].on_wire)) {
                                    current_connection->protocol_id = (PROTOCOL_ID)i;
                                    current_connection->protocol_identified = 1;
                                    break;
                                }
                            }
                        }
                    }
                    if (current_connection->protocol_identified) {
                        http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "Connection delegated to this thread has negotiated the protocol: \"%s\"\n", PROTOCOL_VERSION[current_connection->protocol_id].on_wire);
                    }
                }
                
                if (current_connection->service_buffer_len > 0) {
                    switch (current_connection->protocol_id) {
                        case HTTP1_0:
                            break;
                        case HTTP1_1:
                            printf("<---- HTTP/1.1 Message ------------------------------------------>\n");
                            printf("%.*s\n", current_connection->service_buffer_len, current_connection->service_buffer);
                            printf("<---------------------------------------------------------------->\n\n");
                            
                            if (!current_connection->phttp) {
                                int request_offset = HTTP::check_buffer(current_connection->service_buffer, current_connection->service_buffer_len);
                                if (request_offset >= 0) { /* There was a request found in the buffer */
                                    current_connection->phttp = new HTTP(current_connection->plistener);
                                    if (request_offset > 0) {
                                        http2_buffer_evict_octets(current_connection, request_offset);
                                    }
                                } else {
                                    /* We have data in the buffer, but it's NOT HTTP...*/
                                    http2_error("We have a bad actor here.  We would need to block this IP address.\n");
                                    http2_buffer_evict_octets(current_connection, current_connection->service_buffer_len);
                                    current_connection->connection_is_valid = 0;
                                }
                            } /* NO else here */
                            
                            if (current_connection->phttp) {
                                int h1_bytes_processed = 0;
                                h1_bytes_processed = current_connection->phttp->buffer_http(current_connection->service_buffer, current_connection->service_buffer_len);
                                if (h1_bytes_processed == -1) {
                                    /* PROTOCOL ERROR */
                                    http2_buffer_evict_octets(current_connection, current_connection->service_buffer_len);
                                    current_connection->connection_is_valid = 0;
                                } else if (h1_bytes_processed > 0) {
                                    http2_buffer_evict_octets(current_connection, h1_bytes_processed);
                                } else {
                                    // We got more data, couldn't process it with our open HTTP request. 
                                    // We need to keep an eye on this.  Make sure our buffer doesn't 
                                    // get too big with this WEIRD HTTP request.  And watch our timeout!
                                }
                                if (current_connection->phttp->is_complete()) {
                                    printf("<------- HTTP REQUEST RECEIVED ---------------------------------------->\n");
                                    printf("      METHOD: %s\n", current_connection->phttp->method.val());
                                    printf("        PATH: %s\n", current_connection->phttp->path.val());
                                    printf("    FILENAME: %s\n", current_connection->phttp->filename.val());
                                    printf("QUERY_STRING: %s\n", current_connection->phttp->query_string.val());
                                    printf("HTTP VERSION: %s\n\n", current_connection->phttp->http_version.val());
                                    current_connection->phttp->headers.get_header_list((char **)&_x_buffers, 3000);
                                    printf("*** HEADERS ***\n%s\n\n", _x_buffers);
                                    if (current_connection->phttp->body.length() == 0) {
                                        printf("*** NO BODY ***\n");
                                    } else {
                                        printf("*** BODY: %zu bytes stored ***\n", current_connection->phttp->body.length());
                                    }
                                    printf("<---------------------------------------------------------------------->\n\n");
                                    memset(_x_buffers, 0, 3000);
                                    _x_buffers = 0;
                                    
                                    if (!current_connection->phttp->process_request()) {
                                        http2_error("Failed to assign this request to be processed by an HTTP_SERVER::server() thread!\n");
                                        if (current_connection->phttp->abort_connection() == 1) {
                                            http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "It IS okay to FREE the HTTP object here!\n");
                                            delete current_connection->phttp;
                                        } else {
                                            http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "It is NOT okay to FREE the HTTP object here!\n");
                                        }
                                        current_connection->phttp = 0;
                                        http2_buffer_evict_octets(current_connection, current_connection->service_buffer_len);
                                        current_connection->connection_is_valid = 0;
                                    }
                                } else {
                                    printf("\n******************************************************************\n");
                                    printf(  "* !!!! The HTTP request is NOT complete and ready to serve\n");
                                    printf("\n******************************************************************\n\n");
                                    
                                }
                            }
                            break;
                        case HTTP1_2:
                            break;
                        case WEBSOCKET_ID:
                            /* An HTTP/1.x connection that's been upgraded to 
                             * WebSocket.
                             **/
                            break;
                        case HTTP2_0:
                            /* Here, we're getting hung up. */
                            http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "** Here, this connection thread is getting hung up **\n");
                            http2_process_stream(current_connection);
                            break;
                        default:
                            break;
                    }
                    
                    
                }
                
                
            } /* End loop processing a connection */
            http2_debug(HTTP2_CONNECTION_THREAD, "** Shutting down TLS connection **\n");
            
            /* If this was < HTTP/2 and was handled on the connection level */
            if (current_connection->phttp) {
                if (current_connection->phttp->abort_connection() == 1) {
                    http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "It IS okay to FREE the HTTP object here!\n");
                    delete current_connection->phttp;
                } else {
                    http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "It is NOT okay to FREE the HTTP object here!\n");
                }
                current_connection->phttp = 0;
            }
            
            if (current_connection->ssl) {
                SSL_shutdown(current_connection->ssl);
                SSL_free(current_connection->ssl);
            }
            shutdown(current_connection->socket, 2);
            closesocket(current_connection->socket);

            current_connection->connection_id_dead = 1;
        } else { /* Maybe our semaphore was signalled to shut down or something.. */
            
        }
        
        
    }
    
    http2_debug(HTTP2_CONNECTION_THREAD, "Marking thread as HTTP2_THREAD_SHUTTING_DOWN\n");
    control->status|=HTTP2_THREAD_SHUTTING_DOWN;
    
    if ( (control->status & HTTP2_THREAD_JOIN) != HTTP2_THREAD_JOIN ) {
        /* The join flag is not set so we need to clean up ourselves */
        pthread_detach(pthread_self());
        http2_remove_thread_from_list(control);
        sem_destroy(&control->new_job);
        control->status = HTTP2_THREAD_DEAD;
        free(control);
        http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "Exiting thread after self-terminating and cleanup.\n");
        return 0;
    }
    
    http2_debug(HTTP2_CONNECTION_THREAD, "Thread is EXPECTED to JOIN.\n");
    http2_debug(HTTP2_CONNECTION_THREAD, "Marking this thread as DEAD, NOT freeing HTTP2_CONNECTION_THREAD_CONTROL structure, and done....\n");
    /* The function that called 'retire_http2_connection_thread' and caused this 
     * thread to exit will be responsible for calling http2_remove_thread_from_list() 
     * and cleaning up after this thread.
     */
    http2_debug((HTTP2_CONNECTION_THREAD|HTTP2_VERY_IMPORTANT), "Neatly left http2_connection_thread()\n\n");
    sem_destroy(&control->new_job);
    control->status = HTTP2_THREAD_DEAD;
    return 0;
}


PHTTP2_CONNECTION http2_pop_connection( void ) {
    PHTTP2_CONNECTION c = 0;
    int i = 0;
    http2_lock(http2_connection_backlog_mutex);
    if (http2_connection_backlog_count == 0) {
        http2_unlock(http2_connection_backlog_mutex);
        return HTTP2_NO_BACKLOG;
    }
    
    c = http2_connection_backlog_queue[0];
    for (i = 1; i < http2_connection_backlog_count; i++) {
        http2_connection_backlog_queue[i-1] = 
                http2_connection_backlog_queue[i];
    }
    http2_connection_backlog_queue[--http2_connection_backlog_count] = 0;
    http2_unlock(http2_connection_backlog_mutex);
    return c;
    
}


int http2_push_connection( PHTTP2_CONNECTION c ) {
    http2_lock(http2_connection_backlog_mutex);
    if (HTTP2_MODULE_SETTINGS.max_connection_backlog == http2_connection_backlog_count) {
        http2_unlock(http2_connection_backlog_mutex);
        return HTTP2_ERROR_BACKLOG_FULL;
    }
    http2_connection_backlog_queue[http2_connection_backlog_count++] = c;
    http2_unlock(http2_connection_backlog_mutex);
    return HTTP2_SUCCESS;
}



/** FUNCTION THAT HANDLES CONNECTIONS *****************************************************************************/



/******************************************************************************************************************/



























void http2_buffer_evict_octets( PHTTP2_CONNECTION c, size_t octet_count) {
    if (c->service_buffer_len < octet_count) {
        memmove(c->service_buffer, &c->service_buffer[c->service_buffer_len], c->service_buffer_len-octet_count);
        c->service_buffer_len-=octet_count;
    } else {
        c->service_buffer_len = 0;
    }
    return;
}
