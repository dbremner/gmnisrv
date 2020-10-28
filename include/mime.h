#ifndef GMNISRV_MIME
#define GMNISRV_MIME

void mime_init();
void mime_finish();
const char *mimetype_for_path(const char *path);

#endif
