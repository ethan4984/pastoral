#pragma once

#define BST_GENERIC_SEARCH(ROOT, BASE, VALUE) ({ \
	typeof(ROOT) *_root = ROOT; \
	while(root) { \
		if(root->BASE > (VALUE)) { \
			root = root->left; \
		} else { \
			root = root->right; \
		} \
	} \
	_root \
})

#define BST_GENERIC_INSERT(TABLE_ROOT, BASE, NODE) ({ \
	__label__ out; \
	int ret = 0; \
	typeof(TABLE_ROOT) root = TABLE_ROOT; \
	typeof(TABLE_ROOT) parent = NULL; \
	if((NODE) == NULL) { \
		ret = -1; \
		goto out; \
	} \
	while(root) { \
		parent = root; \
		if(root->BASE > (NODE)->BASE) { \
			root = root->left; \
		} else { \
			root = root->right; \
		} \
	} \
	(NODE)->parent = parent; \
	if(parent == NULL) { \
		TABLE_ROOT = (NODE); \
	} else if(parent->BASE > (NODE)->BASE) { \
		parent->left = (NODE); \
	} else { \
		parent->right = (NODE); \
	} \
out: \
	ret; \
})

#define BST_GENERIC_DELETE(TABLE_ROOT, BASE, NODE) ({ \
	__label__ out; \
	int ret = 0; \
	typeof(NODE) parent = NODE->parent; \
	if((NODE) == NULL) { \
		ret = -1; \
		goto out; \
	} \
	if((NODE)->left == NULL && (NODE)->right == NULL) { \
		if(parent == NULL) { \
			TABLE_ROOT = NULL; \
		} else if(parent->left == (NODE)) { \
			parent->left = NULL; \
		} else { \
			parent->right = NULL; \
		} \
	} else if((NODE)->left && (NODE)->right == NULL) { \
		if(parent->left == (NODE)) { \
			parent->left = (NODE)->left; \
		} else { \
			parent->right = (NODE)->left; \
		} \
	} else if((NODE)->right && (NODE)->left == NULL) { \
		if(parent->left == (NODE)) { \
			parent->left = (NODE)->right; \
		} else { \
			parent->right = (NODE)->right; \
		} \
	} else { \
		if(parent->left == (NODE)) { \
			parent->left = NULL; \
		} else { \
			parent->right = NULL; \
		} \
		BST_GENERIC_INSERT(TABLE_ROOT, BASE, (NODE)->right); \
		BST_GENERIC_INSERT(TABLE_ROOT, BASE, (NODE)->left); \
	} \
out: \
	ret; \
})
