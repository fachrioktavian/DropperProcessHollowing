#ifndef DOWNLOADER_H
#define DOWNLOADER_H

#include <Windows.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Downloads a payload from the specified URL.
	 *
	 * @param url            The URL to download from.
	 * @param payloadBuffer  Output pointer to a heap-allocated buffer containing the payload.
	 * @param payloadSize    Output pointer to the size (in bytes) of the downloaded payload.
	 * @return TRUE if the download succeeded; FALSE otherwise.
	 */

	BOOL GetPayloadFromUrl(LPCWSTR url, PBYTE* payloadBuffer, SIZE_T* payloadSize);

#ifdef __cplusplus
}
#endif

#endif // PAYLOAD_DOWNLOADER_H
#pragma once