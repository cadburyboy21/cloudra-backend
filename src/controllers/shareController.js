const crypto = require('crypto');
const File = require('../models/File');
const Folder = require('../models/Folder');
const User = require('../models/User');

// @desc      Generate share link for a file
// @route     POST /api/files/:id/share
// @access    Private
exports.shareFile = async (req, res, next) => {
    try {
        const { isPublic, expiresIn } = req.body; // expiresIn in hours or specific date
        const file = await File.findOne({ _id: req.params.id, owner: req.user.id });

        if (!file) {
            return res.status(404).json({ success: false, error: 'File not found' });
        }

        // Generate token if not exists or if requested
        if (!file.shareToken) {
            file.shareToken = crypto.randomBytes(16).toString('hex');
        }

        file.isPublic = isPublic !== undefined ? isPublic : file.isPublic;

        if (expiresIn) {
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours() + parseInt(expiresIn));
            file.shareExpiresAt = expiryDate;
        } else if (expiresIn === null) {
            file.shareExpiresAt = null;
        }

        const item = await file.save();
        await item.populate('sharedWith', 'firstName lastName email');

        res.status(200).json({
            success: true,
            data: {
                shareToken: item.shareToken,
                isPublic: item.isPublic,
                shareExpiresAt: item.shareExpiresAt,
                sharedWith: item.sharedWith,
                shareLink: `${process.env.CLIENT_URL || 'https://cloudra-frontend.vercel.app'}/share/${item.shareToken}`
            }
        });
    } catch (err) {
        next(err);
    }
};

// @desc      Generate share link for a folder
// @route     POST /api/folders/:id/share
// @access    Private
exports.shareFolder = async (req, res, next) => {
    try {
        const { isPublic, expiresIn } = req.body;
        const folder = await Folder.findOne({ _id: req.params.id, owner: req.user.id });

        if (!folder) {
            return res.status(404).json({ success: false, error: 'Folder not found' });
        }

        if (!folder.shareToken) {
            folder.shareToken = crypto.randomBytes(16).toString('hex');
        }

        folder.isPublic = isPublic !== undefined ? isPublic : folder.isPublic;

        if (expiresIn) {
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours() + parseInt(expiresIn));
            folder.shareExpiresAt = expiryDate;
        } else if (expiresIn === null) {
            folder.shareExpiresAt = null;
        }

        const item = await folder.save();
        await item.populate('sharedWith', 'firstName lastName email');

        res.status(200).json({
            success: true,
            data: {
                shareToken: item.shareToken,
                isPublic: item.isPublic,
                shareExpiresAt: item.shareExpiresAt,
                sharedWith: item.sharedWith,
                shareLink: `${process.env.CLIENT_URL || 'https://cloudra-frontend.vercel.app'}/share/${item.shareToken}`
            }
        });
    } catch (err) {
        next(err);
    }
};

// @desc      Get shared item by token
// @route     GET /api/share/:token
// @access    Public
exports.getSharedItem = async (req, res, next) => {
    try {
        const { token } = req.params;

        // Try to find in files first
        let item = await File.findOne({ shareToken: token }).populate('owner', 'name email');
        let type = 'file';

        if (!item) {
            item = await Folder.findOne({ shareToken: token }).populate('owner', 'name email');
            type = 'folder';
        }

        if (!item) {
            return res.status(404).json({ success: false, error: 'Shared link is invalid or has been removed' });
        }

        // Check if public
        if (!item.isPublic) {
            // If not public, we need to check if the user is logged in AND is the owner or in sharedWith
            let userId;
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer')) {
                try {
                    const token = authHeader.split(' ')[1];
                    const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
                    userId = decoded.id;
                } catch (e) {
                    // Invalid token, treat as unauthenticated
                }
            }

            const isOwner = userId && item.owner._id.toString() === userId.toString();
            const isShared = userId && item.sharedWith.some(id => id.toString() === userId.toString());

            if (!isOwner && !isShared) {
                return res.status(403).json({ success: false, error: 'Restricted access: This link is private and you don\'t have permission. Please log in with an authorized account.' });
            }
        }

        // Check expiry
        if (item.shareExpiresAt && new Date() > item.shareExpiresAt) {
            return res.status(410).json({ success: false, error: 'This share link has expired' });
        }

        // If it's a folder, we might want to list files in it (if permitted)
        let subItems = [];
        if (type === 'folder') {
            // For now, only return top-level files/folders inside this shared folder
            // In a real app, you'd need recursion or specific permissions
            const files = await File.find({ folder: item._id });
            const folders = await Folder.find({ parent: item._id });
            subItems = { files, folders };
        }

        res.status(200).json({
            success: true,
            data: {
                type,
                item,
                subItems
            }
        });
    } catch (err) {
        next(err);
    }
};

// @desc      Add a user to shared list
// @route     POST /api/files/:id/share/user OR /api/folders/:id/share/user
// @access    Private
exports.addUserToShare = async (req, res, next) => {
    try {
        const { email, type } = req.body; // type is 'file' or 'folder'
        const Model = type === 'file' ? File : Folder;

        const item = await Model.findOne({ _id: req.params.id, owner: req.user.id });
        if (!item) {
            return res.status(404).json({ success: false, error: `${type} not found` });
        }

        const userToAdd = await User.findOne({ email, isActive: true });
        if (!userToAdd) {
            return res.status(404).json({ success: false, error: 'User not found or account not active' });
        }

        if (userToAdd._id.toString() === req.user.id.toString()) {
            return res.status(400).json({ success: false, error: 'You cannot share with yourself' });
        }

        if (item.sharedWith.includes(userToAdd._id)) {
            return res.status(400).json({ success: false, error: 'User already has access' });
        }

        item.sharedWith.push(userToAdd._id);
        await item.save();
        await item.populate('sharedWith', 'firstName lastName email');

        res.status(200).json({
            success: true,
            data: item.sharedWith
        });
    } catch (err) {
        next(err);
    }
};

// @desc      Remove a user from shared list
// @route     DELETE /api/files/:id/share/user/:userId OR /api/folders/:id/share/user/:userId
// @access    Private
exports.removeUserFromShare = async (req, res, next) => {
    try {
        const { type } = req.body;
        const Model = type === 'file' ? File : Folder;

        const item = await Model.findOne({ _id: req.params.id, owner: req.user.id });
        if (!item) {
            return res.status(404).json({ success: false, error: `${type} not found` });
        }

        item.sharedWith = item.sharedWith.filter(uid => uid.toString() !== req.params.userId);
        await item.save();
        await item.populate('sharedWith', 'firstName lastName email');

        res.status(200).json({
            success: true,
            data: item.sharedWith
        });
    } catch (err) {
        next(err);
    }
};

// @desc      Get sharing settings
// @route     GET /api/files/:id/share OR /api/folders/:id/share
// @access    Private
exports.getShareSettings = async (req, res, next) => {
    try {
        const { type } = req.query;
        const Model = type === 'file' ? File : Folder;

        const item = await Model.findOne({ _id: req.params.id, owner: req.user.id })
            .populate('sharedWith', 'firstName lastName email');

        if (!item) {
            return res.status(404).json({ success: false, error: `${type} not found` });
        }

        res.status(200).json({
            success: true,
            data: {
                isPublic: item.isPublic,
                shareToken: item.shareToken,
                shareExpiresAt: item.shareExpiresAt,
                sharedWith: item.sharedWith,
                shareLink: item.shareToken ? `${process.env.CLIENT_URL || 'http://localhost:5173https://cloudra-frontend.vercel.app'}/share/${item.shareToken}` : null
            }
        });
    } catch (err) {
        next(err);
    }
};
