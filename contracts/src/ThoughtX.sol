// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ThoughtX
 * @notice A decentralized, censorship-resistant message posting platform.
 * @dev Supports on-chain text, replies, likes, soft-deletes, multi-chain awareness,
 *      and cryptographic signature-based post restoration across chain resets.
 */
contract ThoughtX {

    struct Thought {
        uint256 id;
        address author;
        string content;
        uint256 timestamp;
        uint256 originalChainId;
        uint256 parentId;      // 0 for root posts, or ID of parent post if this is a reply
        uint256 likesCount;
        bool isDeleted;
    }

    // Auto-incrementing post ID counter
    uint256 private _counter;

    // Thought ID => Thought Data
    mapping(uint256 => Thought) public thoughts;

    // User Address => Array of their Thought IDs
    mapping(address => uint256[]) public userThoughts;

    // Parent Thought ID => Array of reply Thought IDs
    mapping(uint256 => uint256[]) public replies;

    // Thought ID => User Address => Liked Status
    mapping(uint256 => mapping(address => bool)) public hasLiked;

    // Replay attack protection for restored posts: postHash => processed (bool)
    mapping(bytes32 => bool) public executedPostHashes;

    // Events for frontend indexing and real-time UI updates
    event ThoughtPosted(
        uint256 indexed id,
        address indexed author,
        uint256 indexed parentId,
        string content,
        uint256 timestamp,
        uint256 originalChainId
    );

    event ThoughtLiked(uint256 indexed id, address indexed liker);
    event ThoughtUnliked(uint256 indexed id, address indexed unliker);
    event ThoughtDeleted(uint256 indexed id, address indexed author);

    /**
     * @notice Post a new Thought or reply to an existing one.
     * @param content The text of the Thought (max 500 characters).
     * @param parentId Pass 0 for a root thought, or the parent post's ID for a reply.
     */
    function post(string calldata content, uint256 parentId) external returns (uint256) {
        require(bytes(content).length > 0, "Empty content");
        require(bytes(content).length <= 500, "Max 500 characters");
        if (parentId > 0) {
            require(parentId <= _counter, "Parent post does not exist");
            require(!thoughts[parentId].isDeleted, "Cannot reply to deleted post");
        }

        _counter++;
        uint256 newId = _counter;

        thoughts[newId] = Thought({
            id: newId,
            author: msg.sender,
            content: content,
            timestamp: block.timestamp,
            originalChainId: block.chainid,
            parentId: parentId,
            likesCount: 0,
            isDeleted: false
        });

        userThoughts[msg.sender].push(newId);
        if (parentId > 0) {
            replies[parentId].push(newId);
        }

        emit ThoughtPosted(newId, msg.sender, parentId, content, block.timestamp, block.chainid);
        return newId;
    }

    /**
     * @notice Like or unlike a Thought.
     * @param id The ID of the post to like/unlike.
     */
    function toggleLike(uint256 id) external {
        require(id > 0 && id <= _counter, "Thought does not exist");
        require(!thoughts[id].isDeleted, "Cannot like deleted post");

        if (hasLiked[id][msg.sender]) {
            hasLiked[id][msg.sender] = false;
            thoughts[id].likesCount--;
            emit ThoughtUnliked(id, msg.sender);
        } else {
            hasLiked[id][msg.sender] = true;
            thoughts[id].likesCount++;
            emit ThoughtLiked(id, msg.sender);
        }
    }

    /**
     * @notice Soft-delete a thought. Only the original author can call this.
     * @param id The ID of the post to delete.
     */
    function deleteThought(uint256 id) external {
        require(id > 0 && id <= _counter, "Thought does not exist");
        require(thoughts[id].author == msg.sender, "Only author can delete");
        require(!thoughts[id].isDeleted, "Already deleted");

        thoughts[id].content = "[DELETED BY AUTHOR]";
        thoughts[id].isDeleted = true;

        emit ThoughtDeleted(id, msg.sender);
    }

    /**
     * @notice Restore an original post across testnet resets using cryptographic proof.
     * @dev Anyone can pay the gas to submit this; the author is verified by ECDSA signature.
     */
    function restorePostWithSignature(
        address originalAuthor,
        string calldata content,
        uint256 originalTimestamp,
        uint256 originalChainId,
        uint256 parentId,
        bytes calldata signature
    ) external returns (uint256) {
        require(bytes(content).length > 0, "Empty content");
        require(bytes(content).length <= 500, "Max 500 characters");

        // Generate unique hash representing this specific post
        bytes32 postHash = keccak256(
            abi.encodePacked(originalAuthor, content, originalTimestamp, originalChainId, parentId)
        );

        require(!executedPostHashes[postHash], "Post already restored");
        executedPostHashes[postHash] = true;

        // Verify the original author's cryptographic signature
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", postHash)
        );
        address recovered = recoverSigner(ethSignedHash, signature);
        require(recovered == originalAuthor, "Invalid signature: unauthorized author");

        _counter++;
        uint256 newId = _counter;

        thoughts[newId] = Thought({
            id: newId,
            author: originalAuthor,
            content: content,
            timestamp: originalTimestamp,
            originalChainId: originalChainId,
            parentId: parentId,
            likesCount: 0,
            isDeleted: false
        });

        userThoughts[originalAuthor].push(newId);
        if (parentId > 0) {
            replies[parentId].push(newId);
        }

        emit ThoughtPosted(newId, originalAuthor, parentId, content, originalTimestamp, originalChainId);
        return newId;
    }

    /**
     * @notice Fetch paginated global feed in reverse-chronological order.
     * @param cursor The starting post ID to count backwards from (0 starts at latest).
     * @param limit Number of posts to return.
     */
    function getFeed(uint256 cursor, uint256 limit) external view returns (Thought[] memory) {
        if (cursor == 0 || cursor > _counter) cursor = _counter;
        uint256 size = cursor < limit ? cursor : limit;

        Thought[] memory feed = new Thought[](size);
        for (uint256 i = 0; i < size; i++) {
            feed[i] = thoughts[cursor - i];
        }
        return feed;
    }

    /**
     * @notice Get all reply IDs for a specific parent thought.
     */
    function getReplies(uint256 parentId) external view returns (uint256[] memory) {
        return replies[parentId];
    }

    /**
     * @notice Total number of thoughts ever created.
     */
    function totalThoughts() external view returns (uint256) {
        return _counter;
    }

    /**
     * @dev Internal helper for ECDSA signature recovery (built without external imports for ease of compilation)
     */
    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "Invalid signature v value");

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ecrecover failed");
        return signer;
    }
}
