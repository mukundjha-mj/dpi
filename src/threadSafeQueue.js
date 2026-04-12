// ============================================================================
// threadSafeQueue.js - Async queue for passing items between workers
// Converted from: include/thread_safe_queue.h
// ============================================================================
//
// The C++ version uses std::mutex + std::condition_variable to provide
// blocking push/pop across threads.  In Node.js we replace that with a
// simple array queue and a "waiting" list of pending Promise resolvers.
//
// When pop() is called on an empty queue, a Promise is created and parked
// in the waiting array.  The next push() will resolve the oldest waiting
// Promise instead of appending to the queue — mirroring the behaviour of
// condition_variable::notify_one().
//
// ============================================================================

'use strict';

class AsyncQueue {
    /**
     * @param {number} [maxSize=1000]  Maximum items the queue may hold.
     */
    constructor(maxSize = 1000) {
        /** @type {any[]} Internal FIFO buffer */
        this._queue = [];

        /** @type {number} Capacity limit */
        this._maxSize = maxSize;

        /**
         * List of pending pop() resolvers.
         * Each entry is a function `resolve(item)` from an outstanding
         * Promise returned by pop().
         *
         * Mirrors the C++ condition_variable `not_empty_` — waiters are
         * woken (resolved) in FIFO order.
         *
         * @type {Function[]}
         */
        this._waiting = [];
    }

    // ========== Push =======================================================

    /**
     * Push an item onto the queue.
     *
     * If any pop() calls are waiting for data, the oldest waiter is
     * resolved immediately with the item (the item never touches the
     * internal buffer in this case — same as the C++ path where
     * `not_empty_.notify_one()` wakes a blocked consumer).
     *
     * @param {*} item  The item to enqueue.
     * @returns {boolean}  true if the item was accepted, false if the
     *                     queue is at capacity and no waiter is available.
     */
    push(item) {
        // If someone is waiting for data, hand it over directly
        if (this._waiting.length > 0) {
            const resolve = this._waiting.shift();
            resolve(item);
            return true;
        }

        // Otherwise buffer the item (if there is room)
        if (this._queue.length >= this._maxSize) {
            return false;
        }

        this._queue.push(item);
        return true;
    }

    // ========== Pop ========================================================

    /**
     * Pop the next item from the queue.
     *
     * If the queue contains items, the oldest one is returned
     * synchronously (wrapped in an immediately-resolved Promise for
     * a consistent async interface).
     *
     * If the queue is empty, a Promise is returned that will resolve
     * the next time push() is called — mirroring the C++ blocking
     * pop() that waits on `not_empty_`.
     *
     * @returns {Promise<*>}  Resolves with the dequeued item.
     */
    async pop() {
        if (this._queue.length > 0) {
            return this._queue.shift();
        }

        // Park a waiter — will be resolved by the next push()
        return new Promise((resolve) => {
            this._waiting.push(resolve);
        });
    }

    // ========== Inspection =================================================

    /**
     * Current number of buffered items.
     * @returns {number}
     */
    size() {
        return this._queue.length;
    }

    /**
     * Whether the buffer is empty.
     * Note: there may still be pending pop() waiters even when the
     * buffer is empty.
     * @returns {boolean}
     */
    isEmpty() {
        return this._queue.length === 0;
    }

    /**
     * Empty the internal buffer and reject / discard all pending waiters.
     */
    clear() {
        this._queue.length = 0;
        this._waiting.length = 0;
    }
}

module.exports = { AsyncQueue };
