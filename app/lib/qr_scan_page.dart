import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// #0.2 — экран сканирования QR-ссылки камерой (Android/iOS/macOS). Возвращает через `Navigator.pop`
/// первую распознанную непустую строку QR (обычно `citadel://…`) — вызывающий валидирует её как
/// ссылку. Разрешение на камеру запрашивает `mobile_scanner` при старте; отказ/ошибка → `errorBuilder`.
class QrScanPage extends StatefulWidget {
  const QrScanPage({super.key});

  @override
  State<QrScanPage> createState() => _QrScanPageState();
}

class _QrScanPageState extends State<QrScanPage> {
  final MobileScannerController _controller =
      MobileScannerController(formats: const [BarcodeFormat.qrCode]);
  bool _handled = false; // pop только один раз (onDetect зовётся на каждый кадр)

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    for (final b in capture.barcodes) {
      final v = b.rawValue?.trim();
      if (v != null && v.isNotEmpty) {
        _handled = true;
        Navigator.pop(context, v);
        return;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Сканировать QR'),
        actions: [
          IconButton(
            tooltip: 'Фонарик',
            icon: const Icon(Icons.flashlight_on_outlined),
            onPressed: () => _controller.toggleTorch(),
          ),
        ],
      ),
      body: Stack(
        alignment: Alignment.center,
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            errorBuilder: (context, error, child) => _CameraError(error: error),
          ),
          // рамка-подсказка для наведения на QR
          IgnorePointer(
            child: Container(
              width: 240,
              height: 240,
              decoration: BoxDecoration(
                border: Border.all(color: Colors.white70, width: 2),
                borderRadius: BorderRadius.circular(16),
              ),
            ),
          ),
          Positioned(
            bottom: 40,
            left: 24,
            right: 24,
            child: Text(
              'Наведите камеру на QR-код citadel://-ссылки',
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: Colors.white,
                shadows: [Shadow(blurRadius: 6, color: Colors.black)],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _CameraError extends StatelessWidget {
  const _CameraError({required this.error});
  final MobileScannerException error;

  @override
  Widget build(BuildContext context) {
    final denied = error.errorCode == MobileScannerErrorCode.permissionDenied;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(denied ? Icons.no_photography_outlined : Icons.error_outline,
                size: 48, color: Theme.of(context).colorScheme.error),
            const SizedBox(height: 12),
            Text(
              denied
                  ? 'Нет доступа к камере. Разрешите камеру в настройках приложения или вставьте '
                      'ссылку вручную.'
                  : 'Камера недоступна: ${error.errorDetails?.message ?? error.errorCode.name}. '
                      'Вставьте ссылку вручную.',
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
