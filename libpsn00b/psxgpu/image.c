/*
 * PSn00bSDK GPU library (image and VRAM transfer functions)
 * (C) 2022 spicyjpeg - MPL licensed
 *
 * TODO: MoveImage() is currently commented out as it won't trigger a DMA IRQ,
 * making it unusable as a draw queue command. A way around this (perhaps using
 * the GPU IRQ?) shall be found.
 */

#include <stdint.h>
#include <assert.h>
#include <psxgpu.h>
#include <hwregs_c.h>

#define QUEUE_LENGTH		16
#define DMA_CHUNK_LENGTH	8

/* Internal globals */

// LoadImage() and StoreImage() run asynchronously but may be called with a
// pointer to a RECT struct in the stack, which might no longer be valid by the
// time the transfer is actually started. This buffer is used to store a copy
// of all RECTs passed to LoadImage()/StoreImage() as a workaround.
static RECT _saved_rects[QUEUE_LENGTH];
static int  _next_saved_rect = 0;

/* Private utilities */

static void _dma_transfer(const RECT *rect, uint32_t *data, int write) {
	size_t length = rect->w * rect->h;
	if (length % 2)
		_sdk_log("can't transfer an odd number of pixels\n");

	length /= 2;
	if ((length >= DMA_CHUNK_LENGTH) && (length % DMA_CHUNK_LENGTH)) {
		_sdk_log("transfer data length (%d) is not a multiple of %d, rounding\n", length, DMA_CHUNK_LENGTH);
		length += DMA_CHUNK_LENGTH - 1;
	}

	GPU_GP1 = 0x04000000; // Disable DMA request
	GPU_GP0 = 0x01000000; // Flush cache

	GPU_GP0 = write ? 0xa0000000 : 0xc0000000;
	//GPU_GP0 = rect->x | (rect->y << 16);
	GPU_GP0 = *((const uint32_t *) &(rect->x));
	//GPU_GP0 = rect->w | (rect->h << 16);
	GPU_GP0 = *((const uint32_t *) &(rect->w));

	// Enable DMA request, route to GP0 (2) or from GPU_READ (3)
	GPU_GP1 = 0x04000002 | (write ^ 1);

	DMA_MADR(2) = (uint32_t) data;
	if (length < DMA_CHUNK_LENGTH)
		DMA_BCR(2) = 0x00010000 | length;
	else
		DMA_BCR(2) = DMA_CHUNK_LENGTH | ((length / DMA_CHUNK_LENGTH) << 16);

	DMA_CHCR(2) = 0x01000200 | write;
}

/* VRAM transfer API */

int LoadImage(const RECT *rect, const uint32_t *data) {
	int index = _next_saved_rect;

	_saved_rects[index] = *rect;
	_next_saved_rect    = (index + 1) % QUEUE_LENGTH;

	return EnqueueDrawOp(
		(void *)   &_dma_transfer,
		(uint32_t) &_saved_rects[index],
		(uint32_t) data,
		1
	);
}

int StoreImage(const RECT *rect, uint32_t *data) {
	int index = _next_saved_rect;

	_saved_rects[index] = *rect;
	_next_saved_rect    = (index + 1) % QUEUE_LENGTH;

	return EnqueueDrawOp(
		(void *)   &_dma_transfer,
		(uint32_t) &_saved_rects[index],
		(uint32_t) data,
		0
	);
}

void LoadImage2(const RECT *rect, const uint32_t *data) {
	_dma_transfer(rect, (uint32_t *) data, 1);
}

void StoreImage2(const RECT *rect, uint32_t *data) {
	_dma_transfer(rect, data, 0);
}

/*void MoveImage2(const RECT *rect, int x, int y) {
	GPU_GP0 = 0x80000000;
	//GPU_GP0 = rect->x | (rect->y << 16);
	GPU_GP0 = *((const uint32_t *) &(rect->x));
	GPU_GP0 = (x & 0xffff) | (y << 16);
	//GPU_GP0 = rect->w | (rect->h << 16);
	GPU_GP0 = *((const uint32_t *) &(rect->w));
}*/

/* .TIM image parsers */

// This is the only libgs function PSn00bSDK is ever going to implement. The
// difference from GetTimInfo() is that it copies RECTs rather than merely
// returning pointers to them, which become useless once the .TIM file is
// unloaded from main RAM.
int GsGetTimInfo(const uint32_t *tim, GsIMAGE *info) {
	if ((*(tim++) & 0xffff) != 0x0010)
		return 1;

	info->pmode = *(tim++);
	if (info->pmode & 8) {
		const uint32_t *palette_end = tim;
		palette_end += *(tim++) / 4;

		*((uint32_t *) &(info->cx)) = *(tim++);
		*((uint32_t *) &(info->cw)) = *(tim++);
		info->clut = (uint32_t *) tim;

		tim = palette_end;
	} else {
		info->clut = 0;
	}

	tim++;
	*((uint32_t *) &(info->px)) = *(tim++);
	*((uint32_t *) &(info->pw)) = *(tim++);
	info->pixel = (uint32_t *) tim;

	return 0;
}

int GetTimInfo(const uint32_t *tim, TIM_IMAGE *info) {
	if ((*(tim++) & 0xffff) != 0x0010)
		return 1;

	info->mode = *(tim++);
	if (info->mode & 8) {
		const uint32_t *palette_end = tim;
		palette_end += *(tim++) / 4;

		info->crect = (RECT *)     tim;
		info->caddr = (uint32_t *) &tim[2];

		tim = palette_end;
	} else {
		info->caddr = 0;
	}

	tim++;
	info->prect = (RECT *)     tim;
	info->paddr = (uint32_t *) &tim[2];

	return 0;
}
