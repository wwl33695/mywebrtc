/*
 *  Copyright 2015 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#import "WebRTC/RTCDataChannel.h"

#include "webrtc/api/datachannelinterface.h"
#include "webrtc/rtc_base/scoped_ref_ptr.h"

NS_ASSUME_NONNULL_BEGIN

@interface RTCDataBuffer ()

/**
 * The native DataBuffer representation of this RTCDatabuffer object. This is
 * needed to pass to the underlying C++ APIs.
 */
@property(nonatomic, readonly) const webrtc::DataBuffer *nativeDataBuffer;

/** Initialize an RTCDataBuffer from a native DataBuffer. */
- (instancetype)initWithNativeBuffer:(const webrtc::DataBuffer&)nativeBuffer;

@end


@interface RTCDataChannel ()

/** Initialize an RTCDataChannel from a native DataChannelInterface. */
- (instancetype)initWithNativeDataChannel:
    (rtc::scoped_refptr<webrtc::DataChannelInterface>)nativeDataChannel
    NS_DESIGNATED_INITIALIZER;

+ (webrtc::DataChannelInterface::DataState)
    nativeDataChannelStateForState:(RTCDataChannelState)state;

+ (RTCDataChannelState)dataChannelStateForNativeState:
    (webrtc::DataChannelInterface::DataState)nativeState;

+ (NSString *)stringForState:(RTCDataChannelState)state;

@end

NS_ASSUME_NONNULL_END
