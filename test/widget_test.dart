import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:flutter_app/pages/HomePage.dart';
import 'package:flutter_app/widgets/BottomNavBarWidget.dart';

// Flutter tests draw text in a placeholder font that is much wider than real text,
// which makes fixed-width rows "overflow". Load the app's own bundled Roboto so the
// test lays out the way the real app does.
Future<void> loadRoboto() async {
  final loader = FontLoader('Roboto');
  for (final weight in ['Regular', 'Bold', 'Light']) {
    loader.addFont(rootBundle.load('assets/fonts/Roboto-$weight.ttf'));
  }
  await loader.load();
}

void main() {
  testWidgets('Home page renders its title and bottom navigation',
      (WidgetTester tester) async {
    await tester.runAsync(loadRoboto);

    // Phone-sized surface (360 x 720 logical pixels).
    tester.binding.window.physicalSizeTestValue = Size(1080, 2160);
    tester.binding.window.devicePixelRatioTestValue = 3.0;
    addTearDown(tester.binding.window.clearPhysicalSizeTestValue);
    addTearDown(tester.binding.window.clearDevicePixelRatioTestValue);

    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(fontFamily: 'Roboto'),
      home: HomePage(),
    ));
    await tester.pump();

    expect(find.text('What would you like to eat?'), findsOneWidget);
    expect(find.byType(BottomNavBarWidget), findsOneWidget);
  });
}
