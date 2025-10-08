// mobile/lib/services/api_service.dart
import 'package:http/http.dart' as http;
import 'dart:convert';

class ApiService {
  // Replace with your real backend url
  static const String baseUrl = "http://127.0.0.1:8000";

  static Future<Map<String, dynamic>> scanTarget(String target) async {
    final url = Uri.parse("$baseUrl/api/scan");
    final resp = await http.post(url,
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({"target": target}));
    if (resp.statusCode == 200) {
      return jsonDecode(resp.body) as Map<String, dynamic>;
    } else {
      throw Exception("Scan failed: ${resp.statusCode} ${resp.body}");
    }
  }
}
