#pragma once

#include <fs/vfs.h>
#include <vector.h>
#include <hash.h>

struct drm_crtc {

};

struct drm_plane {

};

struct drm_encoder {

};

struct drm_connector {

};

struct drm_framebuffer {

};

struct drm_mode_object {
	
};

struct drm_version {
	int major;
	int minor;
	int patch_level;
	size_t name_length;
	char *name;
	size_t desc_length;
	char *desc;
	size_t date_length;
	char *date;
};

struct drm_driver {
	struct drm_device *device;

	int screen_height;
	int screen_width;
	int screen_pitch;
	void *framebuffer;

	int major;
	int minor;
	int patch_level;

	char *name;
	char *desc;
	char *date;
};

struct drm_device {
	struct vfs_node *vfs_node;

	VECTOR(struct drm_crtc*) crtc_list;
	VECTOR(struct drm_plane*) plane_list;
	VECTOR(struct drm_encoder*) encoder_list;
	VECTOR(struct drm_connector*) connector_list;
	VECTOR(struct drm_framebuffer*) framebuffer_list;

	struct drm_driver *driver;

	struct hash_table object_list;

	uint32_t max_height;
	uint32_t max_width;
	uint32_t min_height;
	uint32_t min_width;
};

void drm_device_probe(struct drm_driver *driver, struct vfs_node *vfs_node);
