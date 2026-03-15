// mobile/lib/main.dart
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'services/api_service.dart';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart'; // ✅ required for saving the file
import 'package:fl_chart/fl_chart.dart';

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
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0F172A), // deep SOC background
        primaryColor: Colors.cyanAccent,
        cardColor: const Color(0xFF1E293B),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF020617),
          elevation: 0,
        ),
        textTheme: const TextTheme(
          bodyMedium: TextStyle(color: Colors.white),
        ),
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

  Map<String,int> countVulns() {

    List vulns = result?['web_scan']?['vulnerabilities'] ?? [];

    int low = 0;
    int medium = 0;
    int high = 0;
    int critical = 0;

    for (var v in vulns) {

      String sev = (v['severity'] ?? '').toString().toUpperCase();

      if (sev == "LOW") low++;
      if (sev == "MEDIUM") medium++;
      if (sev == "HIGH") high++;
      if (sev == "CRITICAL") critical++;
    }

    return {
      "low": low,
      "medium": medium,
      "high": high,
      "critical": critical
    };
  }

  @override
  Widget build(BuildContext ctx) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          "Cyber Risk SOC Dashboard",
          style: TextStyle(letterSpacing: 1.2),
        ),
      ),
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
            
            const SizedBox(height: 12),
            scanningIndicator(loading),
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
                          const SizedBox(height: 16),

                          // SOC DASHBOARD VISUALS
                          
                          securityStatusBanner(
                            result!['result']?['score'] ?? 0
                          ),

                          const SizedBox(height: 12),

                          attackSurfaceGauge(
                            (result!['attack_surface']?['attack_surface_score'] ?? 0).toDouble()
                          ),

                          const SizedBox(height: 12),

                          

                          const SizedBox(height: 12),
                          threatHeatmap(countVulns()),
                          const SizedBox(height: 12),

                          riskTimeline([
                            (result!['result']?['score'] ?? 0).toDouble()
                          ]),

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
// ===============================
// SOC DASHBOARD WIDGETS
// ===============================

// Attack Surface Gauge
Widget attackSurfaceGauge(double score) {
  return Card(
    child: Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        children: [
          const Text("Attack Surface Score",
              style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 10),
          SizedBox(
            height: 180,
            child: PieChart(
              PieChartData(
                startDegreeOffset: 180,
                centerSpaceRadius: 60,
                sectionsSpace: 0,
                sections: [
                  PieChartSectionData(
                    value: score,
                    color: Colors.red,
                    showTitle: false,
                    radius: 40,
                  ),
                  PieChartSectionData(
                    value: 100 - score,
                    color: Colors.grey.shade300,
                    showTitle: false,
                    radius: 40,
                  ),
                ],
              ),
            ),
          ),
          Text("Score: ${score.toInt()}",
              style: const TextStyle(fontSize: 18))
        ],
      ),
    ),
  );
}

// Threat Heatmap
Widget threatHeatmap(Map counts) {
  return Card(
    child: Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        children: [
          const Text("Threat Distribution",
              style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 10),
          SizedBox(
            height: 200,
            child: BarChart(
              BarChartData(
                barGroups: [
                  BarChartGroupData(x: 0, barRods: [
                    BarChartRodData(toY: (counts["low"] ?? 0).toDouble())
                  ]),
                  BarChartGroupData(x: 1, barRods: [
                    BarChartRodData(toY: (counts["medium"] ?? 0).toDouble())
                  ]),
                  BarChartGroupData(x: 2, barRods: [
                    BarChartRodData(toY: (counts["high"] ?? 0).toDouble())
                  ]),
                  BarChartGroupData(x: 3, barRods: [
                    BarChartRodData(toY: (counts["critical"] ?? 0).toDouble())
                  ]),
                ],
              ),
            ),
          ),
        ],
      ),
    ),
  );
}

// Live Risk Timeline
Widget riskTimeline(List scores) {
  return Card(
    child: Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        children: [
          const Text("Live Risk Timeline",
              style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 10),
          SizedBox(
            height: 200,
            child: LineChart(
              LineChartData(
                lineBarsData: [
                  LineChartBarData(
                    spots: scores
                        .asMap()
                        .entries
                        .map((e) =>
                            FlSpot(e.key.toDouble(), e.value.toDouble()))
                        .toList(),
                    isCurved: true,
                    barWidth: 3,
                  )
                ],
              ),
            ),
          ),
        ],
      ),
    ),
  );
}
Widget securityStatusBanner(int score) {

  String status = "SECURE";
  Color color = Colors.green;

  if (score >= 80) {
    status = "CRITICAL RISK";
    color = Colors.red;
  } else if (score >= 60) {
    status = "HIGH RISK";
    color = Colors.orange;
  } else if (score >= 40) {
    status = "MODERATE RISK";
    color = Colors.yellow;
  }

  return Card(
    color: color.withOpacity(0.2),
    child: Padding(
      padding: const EdgeInsets.all(14),
      child: Row(
        children: [
          Icon(Icons.security, color: color, size: 32),
          const SizedBox(width: 12),
          Text(
            "SECURITY STATUS: $status",
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
        ],
      ),
    ),
  );
}
Widget scanningIndicator(bool scanning) {

  if (!scanning) return const SizedBox();

  return Card(
    color: Colors.black,
    child: Padding(
      padding: const EdgeInsets.all(12),
      child: Row(
        children: const [
          Icon(Icons.warning_amber_rounded, color: Colors.red),
          SizedBox(width: 10),
          Text(
            "SCAN IN PROGRESS — ANALYZING TARGET...",
            style: TextStyle(
              color: Colors.red,
              fontWeight: FontWeight.bold,
            ),
          )
        ],
      ),
    ),
  );
}
