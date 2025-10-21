// mobile/lib/main.dart
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'services/api_service.dart';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart'; // ✅ required for saving the file

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await dotenv.load(fileName: ".env");
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Cyber Risk Scanner',
      theme: ThemeData(
        primarySwatch: Colors.indigo,
      ),
      home: const ScanPage(),
    );
  }
}

class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  final TextEditingController _controller = TextEditingController();
  Map<String, dynamic>? result;
  bool loading = false;
  String? error;

  void startScan() async {
    final target = _controller.text.trim();
    if (target.isEmpty) {
      setState(() => error = "Please enter a domain or IP");
      return;
    }

    setState(() {
      loading = true;
      result = null;
      error = null;
    });

    try {
      final res = await ApiService.scanTarget(target);
      setState(() => result = res);
    } catch (e) {
      setState(() => error = e.toString());
    } finally {
      setState(() => loading = false);
    }
  }

  Future<void> downloadReport() async {
    if (result == null) return;
    try {
      final bytes = await ApiService.downloadReport(result!);
      final directory = await getApplicationDocumentsDirectory();
      final file = File("${directory.path}/cyber_report.pdf");
      await file.writeAsBytes(bytes);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("Report saved to ${file.path}")),
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("Failed to generate report: $e")),
      );
    }
  }

  @override
  Widget build(BuildContext ctx) {
    return Scaffold(
      appBar: AppBar(title: const Text("Cyber Risk Scanner")),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(
              controller: _controller,
              decoration: const InputDecoration(
                labelText: "Enter domain or IP",
                border: OutlineInputBorder(),
              ),
              keyboardType: TextInputType.text,
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: startScan,
                child: const Text("Start Scan"),
              ),
            ),
            const SizedBox(height: 16),
            if (loading) const CircularProgressIndicator(),
            if (error != null) ...[
              const SizedBox(height: 12),
              Text(error!, style: const TextStyle(color: Colors.red)),
            ],
            if (result != null)
              Expanded(
                child: SingleChildScrollView(
                  child: Card(
                    margin: const EdgeInsets.only(top: 12),
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            "Target: ${result!['target'] ?? ''}",
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                          const SizedBox(height: 8),
                          Text("Score: ${result!['result']?['score'] ?? 'N/A'}"),
                          Text("Category: ${result!['result']?['category'] ?? 'N/A'}"),
                          const SizedBox(height: 8),
                          const Text("Features:",
                              style: TextStyle(fontWeight: FontWeight.bold)),
                          Text(result!['features']?.toString() ?? ''),
                          const SizedBox(height: 8),
                          const Text("Full JSON:",
                              style: TextStyle(fontWeight: FontWeight.bold)),
                          Text(const JsonEncoder.withIndent('  ').convert(result)),
                          const SizedBox(height: 16),
                          // ✅ Download button
                          ElevatedButton.icon(
                            icon: const Icon(Icons.download),
                            label: const Text("Download Report"),
                            onPressed: downloadReport,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
