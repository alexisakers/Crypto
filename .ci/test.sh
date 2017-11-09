#!/bin/bash
set -e

echo "🛠 Building project in Debug mode"
xcodebuild clean build -project Crypto.xcodeproj -scheme "$SCHEME" -configuration Debug | xcpretty

echo "🛠 Building project in Release mode"
xcodebuild clean build -project Crypto.xcodeproj -scheme "$SCHEME" -configuration Release | xcpretty
    
case $TEST in

'simulator')
    echo "📲 Creating Simulator"
    DEVICE_ID=$(xcrun simctl create $TEST_DEVICE \
                com.apple.CoreSimulator.SimDeviceType.$TEST_DEVICE \
                com.apple.CoreSimulator.SimRuntime.$TEST_RUNTIME)

    echo "🔍 Running unit tests on simulator [$DEVICE_ID]"
    xcrun simctl boot $DEVICE_ID
    xcodebuild clean test -project Crypto.xcodeproj -scheme "$SCHEME" -destination "id=$DEVICE_ID" | xcpretty
;;

'device')
    echo "🔍 Running unit tests on device"
    xcodebuild clean test -project Crypto.xcodeproj -scheme "$SCHEME" -destination "$DESTINATION" | xcpretty
;;

*)
    echo "⏺ No unit tests to run."
;;

esac    