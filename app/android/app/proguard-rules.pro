# CitadelPQVPN — keep-правила для JNI-моста (применяются только при isMinifyEnabled=true).
#
# Движок (Rust) зовёт методы CitadelVpnService ПО ИМЕНИ через JNI-рефлексию — R8/shrinker не
# видит эти вызовы как reachable и вырезает методы в release. Симптом: protectFd(int) исчезает
# из dex → java.lang.NoSuchMethodError → сокет не защищён VpnService.protect() → маршрутная петля
# → туннель up, но интернета нет. Держим весь класс сервиса и все native-методы.

-keep class com.quantumaes.citadelpqvpn.CitadelVpnService { *; }

# JNI native-методы (entry points из .so) и классы, в которых они объявлены.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
