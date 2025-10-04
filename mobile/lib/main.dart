// mobile/lib/main.dart (simplified)
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:url_launcher/url_launcher.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override Widget build(BuildContext ctx) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: Text("Cyber Risk Scanner")),
        body: ScanPage(),
      ),
    );
  }
}

class ScanPage extends StatefulWidget { @override _ScanPageState createState() => _ScanPageState(); }
class _ScanPageState extends State<ScanPage> {
  final _controller = TextEditingController();
  Map<String,dynamic>? result;
  bool loading = false;

  void startScan() async {
    final target = _controller.text.trim();
    if (target.isEmpty) return;
    setState(() { loading=true; result=null; });
    final res = await http.post(Uri.parse("https://YOUR_BACKEND_URL/api/scan"),
      headers: {"Content-Type":"application/json"},
      body: jsonEncode({"target": target})
    );
    if (res.statusCode==200) {
      setState(() { result = jsonDecode(res.body); });
    } else {
      setState(() { result = {"error":"Scan failed"}; });
    }
    setState(() { loading=false; });
  }

  @override Widget build(BuildContext ctx) => Padding(
    padding: EdgeInsets.all(16),
    child: Column(children:[
      TextField(controller: _controller, decoration: InputDecoration(labelText: "Enter domain or IP")),
      SizedBox(height:10),
      ElevatedButton(onPressed: startScan, child: Text("Start Scan")),
      SizedBox(height:20),
      if (loading) CircularProgressIndicator(),
      if (result!=null) 
        Expanded(child: SingleChildScrollView(child: Text(result.toString())))
    ]),
  );
}
