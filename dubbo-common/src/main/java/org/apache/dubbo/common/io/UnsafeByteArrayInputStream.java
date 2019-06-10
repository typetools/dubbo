/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.common.io;

import java.io.IOException;
import java.io.InputStream;

import org.checkerframework.checker.index.qual.GTENegativeOne;
import org.checkerframework.checker.index.qual.IndexFor;
import org.checkerframework.checker.index.qual.IndexOrHigh;
import org.checkerframework.checker.index.qual.LTEqLengthOf;
import org.checkerframework.checker.index.qual.LTLengthOf;
import org.checkerframework.checker.index.qual.NonNegative;

/**
 * UnsafeByteArrayInputStream.
 */
public class UnsafeByteArrayInputStream extends InputStream {
    protected byte[] mData;

    protected @IndexFor("this.mData") int mPosition, mMark = 0;
    protected @IndexOrHigh("this.mData") int mLimit = 0;

    public UnsafeByteArrayInputStream(byte[] buf) {
        this(buf, 0, buf.length);
    }

    public UnsafeByteArrayInputStream(byte[] buf, int offset) {
        this(buf, offset, buf.length - offset);
    }

    public UnsafeByteArrayInputStream(byte[] buf, int offset, int length) {
        mData = buf;
        mPosition = mMark = offset;
        mLimit = Math.min(offset + length, buf.length);
    }

    @Override
    public @GTENegativeOne int read() {
        return (mPosition < mLimit) ? (mData[mPosition++] & 0xff) : -1;
    }

    @Override
    public @GTENegativeOne @LTEqLengthOf("#1") int read(byte[] b, @IndexOrHigh("#1") int off, @NonNegative @LTLengthOf(value = "#1", offset = "#2 - 1") int len) {
        if (b == null) {
            throw new NullPointerException();
        }
        if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        }
        if (mPosition >= mLimit) {
            return -1;
        }
        if (mPosition + len > mLimit) {
            len = mLimit - mPosition;
        }
        if (len <= 0) {
            return 0;
        }
        System.arraycopy(mData, mPosition, b, off, len);
        mPosition += len;
        return len;
    }

    @Override
    public @NonNegative long skip(long len) {
        if (mPosition + len > mLimit) {
            len = mLimit - mPosition;
        }
        if (len <= 0) {
            return 0;
        }
        mPosition += len;
        return len;
    }

    @Override
    public @NonNegative int available() {
        return mLimit - mPosition;
    }

    @Override
    public boolean markSupported() {
        return true;
    }

    @Override
    public void mark(int readAheadLimit) {
        mMark = mPosition;
    }

    @Override
    public void reset() {
        mPosition = mMark;
    }

    @Override
    public void close() throws IOException {
    }

    public int position() {
        return mPosition;
    }

    public void position(@IndexFor("this.mData") int newPosition) {
        mPosition = newPosition;
    }

    public int size() {
        return mData == null ? 0 : mData.length;
    }
}
