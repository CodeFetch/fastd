// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

/**
   \file

   Buffer management
*/

void fastd_buffer_group_init(fastd_buffer_group_id_t gid, size_t count, const size_t len, size_t head_space, size_t tail_space) {
	struct fastd_buffer_group_entry[] *entries = fastd_new_array(count, struct fastd_buffer_group_entry);

	if (gid >= BUFFER_GROUP_MAX)
		exit_bug("buffergroup");

	ctx.buffers[gid].entries = entries;
	ctx.buffers[gid].count = count;
	ctx.buffers[gid].len = len;
	ctx.buffers[gid].head_space = head_space;

	for (int i = 0; i < count; i++) {
		entries[i].bid = i;
		entries[i].gid = gid;
		entries[i].next = ctx.buffers[gid].head;
		entries[i].buf = fastd_buffer_alloc(len, head_space, tail_space);
		ctx.buffers[gid].head = entries[i];
	}
}
