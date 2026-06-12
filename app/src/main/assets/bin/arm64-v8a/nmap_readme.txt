This folder is designated for pre-compiled Android Nmap binaries.
To bundle Nmap inside your Android application:
1. Compile or download Nmap binaries compiled for Android architectures (e.g. arm64-v8a, armeabi-v7a, x86_64).
2. Replace this placeholder structure with the executable file named 'nmap'.
3. The app is fully configured to copy, set permissions (chmod 755), and run it natively via ProcessBuilder at runtime.
