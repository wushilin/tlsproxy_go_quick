package main

// Windows cannot FlushFileBuffers on the read-only directory handle returned
// by os.Open. The file itself has already been synced before its rename;
// Go does not expose a portable way to sync the directory metadata here.
func syncDirectory(_ string) error { return nil }
