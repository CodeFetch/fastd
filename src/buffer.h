// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Buffer management
*/


#pragma once

#include "alloc.h"


/** A buffer descriptor */
struct fastd_buffer {
	void *base;      /**< The beginning of the allocated memory area */
	size_t base_len; /**< The size of the allocated memory area */

	void *data; /**< The beginning of the actual data in the buffer */
	size_t len; /**< The data length */
};

struct fastd_buffer_group_entry {
	fastd_buffer_t buf;
	fastd_buffer_group_id_t gid;
	size_t bid;
	struct fastd_buffer_group_entry *next;
}

struct fastd_buffer_group {
	unsigned count; /**< The number of buffers contained */
	size_t len; /**< The size of a single allocated memory area */
	size_t head_space;
	struct fastd_buffer_group_entry *head;
	struct fastd_buffer_group_entry *tail;
	struct fastd_buffer_group_entry[] *entries;
}

/**
   Allocate a new buffer

   A buffer can have head and tail space which allows changing with data size without moving the data.

   The buffer is always allocated aligned to 16 bytes to allow efficient access for SIMD instructions
   etc. in crypto implementations
*/
static inline fastd_buffer_t fastd_buffer_alloc(const size_t len, size_t head_space, size_t tail_space) {
	size_t base_len = head_space + len + tail_space;
	void *ptr = fastd_alloc_aligned(base_len, 16);

	return (fastd_buffer_t){ .base = ptr, .base_len = base_len, .data = ptr + head_space, .len = len };
}

/** Duplicates a buffer */
static inline fastd_buffer_t fastd_buffer_dup(const fastd_buffer_t buffer, size_t head_space, size_t tail_space) {
	fastd_buffer_t new_buffer = fastd_buffer_alloc(buffer.len, head_space, tail_space);
	memcpy(new_buffer.data, buffer.data, buffer.len);
	return new_buffer;
}

/** Frees a buffer */
static inline void fastd_buffer_free(fastd_buffer_t buffer) {
	free(buffer.base);
}


/** Pulls the data head (decreases the head space) */
static inline void fastd_buffer_pull_head(fastd_buffer_t *buffer, size_t len) {
	if (len > (size_t)(buffer->data - buffer->base))
		exit_bug("tried to pull buffer across base");

	buffer->data -= len;
	buffer->len += len;
}

/** Pulls the data head and fills with zeroes */
static inline void fastd_buffer_pull_head_zero(fastd_buffer_t *buffer, size_t len) {
	fastd_buffer_pull_head(buffer, len);
	memset(buffer->data, 0, len);
}

/** Pulls the data head and copies data into the new space */
static inline void fastd_buffer_pull_head_from(fastd_buffer_t *buffer, const void *data, size_t len) {
	fastd_buffer_pull_head(buffer, len);
	memcpy(buffer->data, data, len);
}


/** Pushes the buffer head (increases the head space) */
static inline void fastd_buffer_push_head(fastd_buffer_t *buffer, size_t len) {
	if (buffer->len < len)
		exit_bug("tried to push buffer across tail");

	buffer->data += len;
	buffer->len -= len;
}

/** Pushes the buffer head, copying the removed buffer data somewhere else */
static inline void fastd_buffer_push_head_to(fastd_buffer_t *buffer, void *data, size_t len) {
	memcpy(data, buffer->data, len);
	fastd_buffer_push_head(buffer, len);
}

void fastd_buffer_group_init(int gid, unsigned count, const size_t len, size_t head_space, size_t tail_space);

/** Acquires an unused buffer from a buffer group */
static inline fastd_buffer_group_entry *fastd_buffer_group_entry_acquire(int gid) {
	struct fastd_buffer_group_entry *entry = ctx.buffers[gid].head;
	
	if (!entry)
		exit_bug("buffer_acquire");

	ctx.buffers[gid].head = entry->next;
	
	entry->buf->data = entry->buf->base + ctx.buffers[gid].head_space;
	entry->buf->len = ctx.buffers[gid].len;

	return entry;
}

/** Releases a buffer to a buffer group */
static inline void fastd_buffer_release(fastd_buffer_t *buf) {
	struct fastd_buffer_group_entry *entry = container_of(buf, struct fastd_buffer_group_entry, fd);
	entry->next = NULL;
	ctx.buffers[entry->gid].tail->next = entry;
}
