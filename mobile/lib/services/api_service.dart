// mobile/lib/services/api_service.dart
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:typed_data';

class ApiService {
  // Local backend URL
  static const String baseUrl = "http://127.0.0.1:8000";

  // Run the vulnerability scan
  static Future<Map<String, dynamic>> scanTarget(String target) async {
    final url = Uri.parse("$baseUrl/api/scan");
    final resp = await http.post(
      url,
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({"target": target}),
    );

    if (resp.statusCode == 200) {
      return jsonDecode(resp.body) as Map<String, dynamic>;
    } else {
      throw Exception("Scan failed: ${resp.statusCode} ${resp.body}");
    }
  }

  // Generate and download the PDF report
  static Future<Uint8List> downloadReport(Map<String, dynamic> scanResult) async {
    final url = Uri.parse("$baseUrl/api/report");
    final resp = await http.post(
      url,
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "target": scanResult["target"],
        "result": scanResult["result"],
        "osint": scanResult["osint"],
      }),
    );

    if (resp.statusCode == 200) {
      return resp.bodyBytes;
    } else {
      throw Exception("Report generation failed: ${resp.statusCode} ${resp.body}");
    }
  }
}
