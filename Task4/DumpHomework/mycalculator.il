
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.6.1055.0
//  Copyright (c) Microsoft Corporation.  All rights reserved.



// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern PresentationFramework
{
  .publickeytoken = (31 BF 38 56 AD 36 4E 35 )                         // 1.8V.6N5
  .ver 4:0:0:0
}
.assembly extern System
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System.Xaml
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern PresentationCore
{
  .publickeytoken = (31 BF 38 56 AD 36 4E 35 )                         // 1.8V.6N5
  .ver 4:0:0:0
}
.assembly MyCalculatorv1
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.

  // --- The following custom attribute is added automatically, do not uncomment -------
  //  .custom instance void [mscorlib]System.Diagnostics.DebuggableAttribute::.ctor(valuetype [mscorlib]System.Diagnostics.DebuggableAttribute/DebuggingModes) = ( 01 00 07 01 00 00 00 00 ) 

  .custom instance void [mscorlib]System.Reflection.AssemblyTitleAttribute::.ctor(string) = ( 01 00 0E 4D 79 43 61 6C 63 75 6C 61 74 6F 72 76   // ...MyCalculatorv
                                                                                              31 00 00 )                                        // 1..
  .custom instance void [mscorlib]System.Reflection.AssemblyDescriptionAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyConfigurationAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyCompanyAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyProductAttribute::.ctor(string) = ( 01 00 0E 4D 79 43 61 6C 63 75 6C 61 74 6F 72 76   // ...MyCalculatorv
                                                                                                31 00 00 )                                        // 1..
  .custom instance void [mscorlib]System.Reflection.AssemblyCopyrightAttribute::.ctor(string) = ( 01 00 12 43 6F 70 79 72 69 67 68 74 20 C2 A9 20   // ...Copyright .. 
                                                                                                  20 32 30 31 32 00 00 )                            //  2012..
  .custom instance void [mscorlib]System.Reflection.AssemblyTrademarkAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ComVisibleAttribute::.ctor(bool) = ( 01 00 00 00 00 ) 
  .custom instance void [PresentationFramework]System.Windows.ThemeInfoAttribute::.ctor(valuetype [PresentationFramework]System.Windows.ResourceDictionaryLocation,
                                                                                        valuetype [PresentationFramework]System.Windows.ResourceDictionaryLocation) = ( 01 00 00 00 00 00 01 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyFileVersionAttribute::.ctor(string) = ( 01 00 07 31 2E 30 2E 30 2E 30 00 00 )             // ...1.0.0.0..
  .custom instance void [mscorlib]System.Runtime.Versioning.TargetFrameworkAttribute::.ctor(string) = ( 01 00 1A 2E 4E 45 54 46 72 61 6D 65 77 6F 72 6B   // ....NETFramework
                                                                                                        2C 56 65 72 73 69 6F 6E 3D 76 34 2E 35 01 00 54   // ,Version=v4.5..T
                                                                                                        0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C   // ..FrameworkDispl
                                                                                                        61 79 4E 61 6D 65 12 2E 4E 45 54 20 46 72 61 6D   // ayName..NET Fram
                                                                                                        65 77 6F 72 6B 20 34 2E 35 )                      // ework 4.5
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.mresource public MyCalculatorv1.g.resources
{
  // Offset: 0x00000000 Length: 0x00001918
  // WARNING: managed resource file MyCalculatorv1.g.resources created
}
.mresource public MyCalculatorv1.Properties.Resources.resources
{
  // Offset: 0x00001920 Length: 0x000000B4
  // WARNING: managed resource file MyCalculatorv1.Properties.Resources.resources created
}
.module MyCalculatorv1.exe
// MVID: {8E4247A5-25E4-47A6-84F4-A414933F7536}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0002       // WINDOWS_GUI
.corflags 0x00020003    //  ILONLY 32BITPREFERRED
// Image base: 0x03250000


// =============== CLASS MEMBERS DECLARATION ===================

.class public auto ansi beforefieldinit MyCalculatorv1.App
       extends [PresentationFramework]System.Windows.Application
{
  .method public hidebysig instance void 
          InitializeComponent() cil managed
  {
    .custom instance void [mscorlib]System.Diagnostics.DebuggerNonUserCodeAttribute::.ctor() = ( 01 00 00 00 ) 
    .custom instance void [System]System.CodeDom.Compiler.GeneratedCodeAttribute::.ctor(string,
                                                                                        string) = ( 01 00 16 50 72 65 73 65 6E 74 61 74 69 6F 6E 42   // ...PresentationB
                                                                                                    75 69 6C 64 54 61 73 6B 73 07 34 2E 30 2E 30 2E   // uildTasks.4.0.0.
                                                                                                    30 00 00 )                                        // 0..
    // Code size       20 (0x14)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldstr      "MainWindow.xaml"
    IL_0007:  ldc.i4.2
    IL_0008:  newobj     instance void [System]System.Uri::.ctor(string,
                                                                 valuetype [System]System.UriKind)
    IL_000d:  call       instance void [PresentationFramework]System.Windows.Application::set_StartupUri(class [System]System.Uri)
    IL_0012:  nop
    IL_0013:  ret
  } // end of method App::InitializeComponent

  .method public hidebysig static void  Main() cil managed
  {
    .entrypoint
    .custom instance void [mscorlib]System.STAThreadAttribute::.ctor() = ( 01 00 00 00 ) 
    .custom instance void [mscorlib]System.Diagnostics.DebuggerNonUserCodeAttribute::.ctor() = ( 01 00 00 00 ) 
    .custom instance void [System]System.CodeDom.Compiler.GeneratedCodeAttribute::.ctor(string,
                                                                                        string) = ( 01 00 16 50 72 65 73 65 6E 74 61 74 69 6F 6E 42   // ...PresentationB
                                                                                                    75 69 6C 64 54 61 73 6B 73 07 34 2E 30 2E 30 2E   // uildTasks.4.0.0.
                                                                                                    30 00 00 )                                        // 0..
    // Code size       22 (0x16)
    .maxstack  1
    .locals init (class MyCalculatorv1.App V_0)
    IL_0000:  nop
    IL_0001:  newobj     instance void MyCalculatorv1.App::.ctor()
    IL_0006:  stloc.0
    IL_0007:  ldloc.0
    IL_0008:  callvirt   instance void MyCalculatorv1.App::InitializeComponent()
    IL_000d:  nop
    IL_000e:  ldloc.0
    IL_000f:  callvirt   instance int32 [PresentationFramework]System.Windows.Application::Run()
    IL_0014:  pop
    IL_0015:  ret
  } // end of method App::Main

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [PresentationFramework]System.Windows.Application::.ctor()
    IL_0006:  nop
    IL_0007:  ret
  } // end of method App::.ctor

} // end of class MyCalculatorv1.App

.class public auto ansi beforefieldinit MyCalculatorv1.MainWindow
       extends [PresentationFramework]System.Windows.Window
       implements [System.Xaml]System.Windows.Markup.IComponentConnector
{
  .field assembly class [PresentationFramework]System.Windows.Controls.TextBox tb
  .field private bool _contentLoaded
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       16 (0x10)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [PresentationFramework]System.Windows.Window::.ctor()
    IL_0006:  nop
    IL_0007:  nop
    IL_0008:  ldarg.0
    IL_0009:  call       instance void MyCalculatorv1.MainWindow::InitializeComponent()
    IL_000e:  nop
    IL_000f:  ret
  } // end of method MainWindow::.ctor

  .method private hidebysig instance void 
          Button_Click_1(object sender,
                         class [PresentationCore]System.Windows.RoutedEventArgs e) cil managed
  {
    // Code size       45 (0x2d)
    .maxstack  3
    .locals init (class [PresentationFramework]System.Windows.Controls.Button V_0,
             class [PresentationFramework]System.Windows.Controls.TextBox V_1)
    IL_0000:  nop
    IL_0001:  ldarg.1
    IL_0002:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0007:  stloc.0
    IL_0008:  ldarg.0
    IL_0009:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_000e:  stloc.1
    IL_000f:  ldloc.1
    IL_0010:  ldloc.1
    IL_0011:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0016:  ldloc.0
    IL_0017:  callvirt   instance object [PresentationFramework]System.Windows.Controls.ContentControl::get_Content()
    IL_001c:  callvirt   instance string [mscorlib]System.Object::ToString()
    IL_0021:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0026:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_002b:  nop
    IL_002c:  ret
  } // end of method MainWindow::Button_Click_1

  .method private hidebysig instance void 
          Result_click(object sender,
                       class [PresentationCore]System.Windows.RoutedEventArgs e) cil managed
  {
    // Code size       9 (0x9)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  call       instance void MyCalculatorv1.MainWindow::result()
    IL_0007:  nop
    IL_0008:  ret
  } // end of method MainWindow::Result_click

  .method private hidebysig instance void 
          result() cil managed
  {
    // Code size       541 (0x21d)
    .maxstack  5
    .locals init (string V_0,
             int32 V_1,
             float64 V_2,
             float64 V_3,
             bool V_4,
             bool V_5,
             bool V_6,
             bool V_7,
             bool V_8,
             class [PresentationFramework]System.Windows.Controls.TextBox V_9,
             bool V_10,
             bool V_11)
    IL_0000:  nop
    IL_0001:  ldc.i4.0
    IL_0002:  stloc.1
    IL_0003:  ldarg.0
    IL_0004:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0009:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_000e:  ldstr      "+"
    IL_0013:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_0018:  stloc.s    V_4
    IL_001a:  ldloc.s    V_4
    IL_001c:  brfalse.s  IL_003b

    IL_001e:  nop
    IL_001f:  ldarg.0
    IL_0020:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0025:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_002a:  ldstr      "+"
    IL_002f:  callvirt   instance int32 [mscorlib]System.String::IndexOf(string)
    IL_0034:  stloc.1
    IL_0035:  nop
    IL_0036:  br         IL_00dc

    IL_003b:  ldarg.0
    IL_003c:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0041:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0046:  ldstr      "-"
    IL_004b:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_0050:  stloc.s    V_5
    IL_0052:  ldloc.s    V_5
    IL_0054:  brfalse.s  IL_0070

    IL_0056:  nop
    IL_0057:  ldarg.0
    IL_0058:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_005d:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0062:  ldstr      "-"
    IL_0067:  callvirt   instance int32 [mscorlib]System.String::IndexOf(string)
    IL_006c:  stloc.1
    IL_006d:  nop
    IL_006e:  br.s       IL_00dc

    IL_0070:  ldarg.0
    IL_0071:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0076:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_007b:  ldstr      "*"
    IL_0080:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_0085:  stloc.s    V_6
    IL_0087:  ldloc.s    V_6
    IL_0089:  brfalse.s  IL_00a5

    IL_008b:  nop
    IL_008c:  ldarg.0
    IL_008d:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0092:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0097:  ldstr      "*"
    IL_009c:  callvirt   instance int32 [mscorlib]System.String::IndexOf(string)
    IL_00a1:  stloc.1
    IL_00a2:  nop
    IL_00a3:  br.s       IL_00dc

    IL_00a5:  ldarg.0
    IL_00a6:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_00ab:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_00b0:  ldstr      "/"
    IL_00b5:  callvirt   instance bool [mscorlib]System.String::Contains(string)
    IL_00ba:  stloc.s    V_7
    IL_00bc:  ldloc.s    V_7
    IL_00be:  brfalse.s  IL_00da

    IL_00c0:  nop
    IL_00c1:  ldarg.0
    IL_00c2:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_00c7:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_00cc:  ldstr      "/"
    IL_00d1:  callvirt   instance int32 [mscorlib]System.String::IndexOf(string)
    IL_00d6:  stloc.1
    IL_00d7:  nop
    IL_00d8:  br.s       IL_00dc

    IL_00da:  nop
    IL_00db:  nop
    IL_00dc:  ldarg.0
    IL_00dd:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_00e2:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_00e7:  ldloc.1
    IL_00e8:  ldc.i4.1
    IL_00e9:  callvirt   instance string [mscorlib]System.String::Substring(int32,
                                                                            int32)
    IL_00ee:  stloc.0
    IL_00ef:  ldarg.0
    IL_00f0:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_00f5:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_00fa:  ldc.i4.0
    IL_00fb:  ldloc.1
    IL_00fc:  callvirt   instance string [mscorlib]System.String::Substring(int32,
                                                                            int32)
    IL_0101:  call       float64 [mscorlib]System.Convert::ToDouble(string)
    IL_0106:  stloc.2
    IL_0107:  ldarg.0
    IL_0108:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_010d:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0112:  ldloc.1
    IL_0113:  ldc.i4.1
    IL_0114:  add
    IL_0115:  ldarg.0
    IL_0116:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_011b:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0120:  callvirt   instance int32 [mscorlib]System.String::get_Length()
    IL_0125:  ldloc.1
    IL_0126:  sub
    IL_0127:  ldc.i4.1
    IL_0128:  sub
    IL_0129:  callvirt   instance string [mscorlib]System.String::Substring(int32,
                                                                            int32)
    IL_012e:  call       float64 [mscorlib]System.Convert::ToDouble(string)
    IL_0133:  stloc.3
    IL_0134:  ldloc.0
    IL_0135:  ldstr      "+"
    IL_013a:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_013f:  stloc.s    V_8
    IL_0141:  ldloc.s    V_8
    IL_0143:  brfalse.s  IL_0175

    IL_0145:  nop
    IL_0146:  ldarg.0
    IL_0147:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_014c:  stloc.s    V_9
    IL_014e:  ldloc.s    V_9
    IL_0150:  ldloc.s    V_9
    IL_0152:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0157:  ldstr      "="
    IL_015c:  ldloc.2
    IL_015d:  ldloc.3
    IL_015e:  add
    IL_015f:  box        [mscorlib]System.Double
    IL_0164:  call       string [mscorlib]System.String::Concat(object,
                                                                object,
                                                                object)
    IL_0169:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_016e:  nop
    IL_016f:  nop
    IL_0170:  br         IL_021c

    IL_0175:  ldloc.0
    IL_0176:  ldstr      "-"
    IL_017b:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0180:  stloc.s    V_10
    IL_0182:  ldloc.s    V_10
    IL_0184:  brfalse.s  IL_01b3

    IL_0186:  nop
    IL_0187:  ldarg.0
    IL_0188:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_018d:  stloc.s    V_9
    IL_018f:  ldloc.s    V_9
    IL_0191:  ldloc.s    V_9
    IL_0193:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0198:  ldstr      "="
    IL_019d:  ldloc.2
    IL_019e:  ldloc.3
    IL_019f:  sub
    IL_01a0:  box        [mscorlib]System.Double
    IL_01a5:  call       string [mscorlib]System.String::Concat(object,
                                                                object,
                                                                object)
    IL_01aa:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_01af:  nop
    IL_01b0:  nop
    IL_01b1:  br.s       IL_021c

    IL_01b3:  ldloc.0
    IL_01b4:  ldstr      "*"
    IL_01b9:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_01be:  stloc.s    V_11
    IL_01c0:  ldloc.s    V_11
    IL_01c2:  brfalse.s  IL_01f1

    IL_01c4:  nop
    IL_01c5:  ldarg.0
    IL_01c6:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_01cb:  stloc.s    V_9
    IL_01cd:  ldloc.s    V_9
    IL_01cf:  ldloc.s    V_9
    IL_01d1:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_01d6:  ldstr      "="
    IL_01db:  ldloc.2
    IL_01dc:  ldloc.3
    IL_01dd:  mul
    IL_01de:  box        [mscorlib]System.Double
    IL_01e3:  call       string [mscorlib]System.String::Concat(object,
                                                                object,
                                                                object)
    IL_01e8:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_01ed:  nop
    IL_01ee:  nop
    IL_01ef:  br.s       IL_021c

    IL_01f1:  nop
    IL_01f2:  ldarg.0
    IL_01f3:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_01f8:  stloc.s    V_9
    IL_01fa:  ldloc.s    V_9
    IL_01fc:  ldloc.s    V_9
    IL_01fe:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0203:  ldstr      "="
    IL_0208:  ldloc.2
    IL_0209:  ldloc.3
    IL_020a:  div
    IL_020b:  box        [mscorlib]System.Double
    IL_0210:  call       string [mscorlib]System.String::Concat(object,
                                                                object,
                                                                object)
    IL_0215:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_021a:  nop
    IL_021b:  nop
    IL_021c:  ret
  } // end of method MainWindow::result

  .method private hidebysig instance void 
          Off_Click_1(object sender,
                      class [PresentationCore]System.Windows.RoutedEventArgs e) cil managed
  {
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  call       class [PresentationFramework]System.Windows.Application [PresentationFramework]System.Windows.Application::get_Current()
    IL_0006:  callvirt   instance void [PresentationFramework]System.Windows.Application::Shutdown()
    IL_000b:  nop
    IL_000c:  ret
  } // end of method MainWindow::Off_Click_1

  .method private hidebysig instance void 
          Del_Click(object sender,
                    class [PresentationCore]System.Windows.RoutedEventArgs e) cil managed
  {
    // Code size       19 (0x13)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0007:  ldstr      ""
    IL_000c:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_0011:  nop
    IL_0012:  ret
  } // end of method MainWindow::Del_Click

  .method private hidebysig instance void 
          R_Click(object sender,
                  class [PresentationCore]System.Windows.RoutedEventArgs e) cil managed
  {
    // Code size       74 (0x4a)
    .maxstack  5
    .locals init (bool V_0)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0007:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_000c:  callvirt   instance int32 [mscorlib]System.String::get_Length()
    IL_0011:  ldc.i4.0
    IL_0012:  cgt
    IL_0014:  stloc.0
    IL_0015:  ldloc.0
    IL_0016:  brfalse.s  IL_0049

    IL_0018:  nop
    IL_0019:  ldarg.0
    IL_001a:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_001f:  ldarg.0
    IL_0020:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0025:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_002a:  ldc.i4.0
    IL_002b:  ldarg.0
    IL_002c:  ldfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0031:  callvirt   instance string [PresentationFramework]System.Windows.Controls.TextBox::get_Text()
    IL_0036:  callvirt   instance int32 [mscorlib]System.String::get_Length()
    IL_003b:  ldc.i4.1
    IL_003c:  sub
    IL_003d:  callvirt   instance string [mscorlib]System.String::Substring(int32,
                                                                            int32)
    IL_0042:  callvirt   instance void [PresentationFramework]System.Windows.Controls.TextBox::set_Text(string)
    IL_0047:  nop
    IL_0048:  nop
    IL_0049:  ret
  } // end of method MainWindow::R_Click

  .method public hidebysig newslot virtual final 
          instance void  InitializeComponent() cil managed
  {
    .custom instance void [mscorlib]System.Diagnostics.DebuggerNonUserCodeAttribute::.ctor() = ( 01 00 00 00 ) 
    .custom instance void [System]System.CodeDom.Compiler.GeneratedCodeAttribute::.ctor(string,
                                                                                        string) = ( 01 00 16 50 72 65 73 65 6E 74 61 74 69 6F 6E 42   // ...PresentationB
                                                                                                    75 69 6C 64 54 61 73 6B 73 07 34 2E 30 2E 30 2E   // uildTasks.4.0.0.
                                                                                                    30 00 00 )                                        // 0..
    // Code size       42 (0x2a)
    .maxstack  2
    .locals init (class [System]System.Uri V_0,
             bool V_1)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      bool MyCalculatorv1.MainWindow::_contentLoaded
    IL_0007:  stloc.1
    IL_0008:  ldloc.1
    IL_0009:  brfalse.s  IL_000e

    IL_000b:  nop
    IL_000c:  br.s       IL_0029

    IL_000e:  ldarg.0
    IL_000f:  ldc.i4.1
    IL_0010:  stfld      bool MyCalculatorv1.MainWindow::_contentLoaded
    IL_0015:  ldstr      "/MyCalculatorv1;component/mainwindow.xaml"
    IL_001a:  ldc.i4.2
    IL_001b:  newobj     instance void [System]System.Uri::.ctor(string,
                                                                 valuetype [System]System.UriKind)
    IL_0020:  stloc.0
    IL_0021:  ldarg.0
    IL_0022:  ldloc.0
    IL_0023:  call       void [PresentationFramework]System.Windows.Application::LoadComponent(object,
                                                                                               class [System]System.Uri)
    IL_0028:  nop
    IL_0029:  ret
  } // end of method MainWindow::InitializeComponent

  .method private hidebysig newslot virtual final 
          instance void  System.Windows.Markup.IComponentConnector.Connect(int32 connectionId,
                                                                           object target) cil managed
  {
    .custom instance void [mscorlib]System.Diagnostics.DebuggerNonUserCodeAttribute::.ctor() = ( 01 00 00 00 ) 
    .custom instance void [System]System.CodeDom.Compiler.GeneratedCodeAttribute::.ctor(string,
                                                                                        string) = ( 01 00 16 50 72 65 73 65 6E 74 61 74 69 6F 6E 42   // ...PresentationB
                                                                                                    75 69 6C 64 54 61 73 6B 73 07 34 2E 30 2E 30 2E   // uildTasks.4.0.0.
                                                                                                    30 00 00 )                                        // 0..
    .custom instance void [System]System.ComponentModel.EditorBrowsableAttribute::.ctor(valuetype [System]System.ComponentModel.EditorBrowsableState) = ( 01 00 01 00 00 00 00 00 ) 
    .override [System.Xaml]System.Windows.Markup.IComponentConnector::Connect
    // Code size       624 (0x270)
    .maxstack  3
    .locals init (int32 V_0)
    IL_0000:  nop
    IL_0001:  ldarg.1
    IL_0002:  stloc.0
    IL_0003:  ldloc.0
    IL_0004:  ldc.i4.1
    IL_0005:  sub
    IL_0006:  switch     ( 
                          IL_005c,
                          IL_0079,
                          IL_008a,
                          IL_00a7,
                          IL_00c4,
                          IL_00e1,
                          IL_00fe,
                          IL_011b,
                          IL_0138,
                          IL_0155,
                          IL_0172,
                          IL_018f,
                          IL_01ac,
                          IL_01c9,
                          IL_01e6,
                          IL_0200,
                          IL_021a,
                          IL_0234,
                          IL_024e)
    IL_0057:  br         IL_0268

    IL_005c:  ldarg.2
    IL_005d:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0062:  ldarg.0
    IL_0063:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0069:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_006e:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0073:  nop
    IL_0074:  br         IL_026f

    IL_0079:  ldarg.0
    IL_007a:  ldarg.2
    IL_007b:  castclass  [PresentationFramework]System.Windows.Controls.TextBox
    IL_0080:  stfld      class [PresentationFramework]System.Windows.Controls.TextBox MyCalculatorv1.MainWindow::tb
    IL_0085:  br         IL_026f

    IL_008a:  ldarg.2
    IL_008b:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0090:  ldarg.0
    IL_0091:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0097:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_009c:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_00a1:  nop
    IL_00a2:  br         IL_026f

    IL_00a7:  ldarg.2
    IL_00a8:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_00ad:  ldarg.0
    IL_00ae:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_00b4:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_00b9:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_00be:  nop
    IL_00bf:  br         IL_026f

    IL_00c4:  ldarg.2
    IL_00c5:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_00ca:  ldarg.0
    IL_00cb:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_00d1:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_00d6:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_00db:  nop
    IL_00dc:  br         IL_026f

    IL_00e1:  ldarg.2
    IL_00e2:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_00e7:  ldarg.0
    IL_00e8:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_00ee:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_00f3:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_00f8:  nop
    IL_00f9:  br         IL_026f

    IL_00fe:  ldarg.2
    IL_00ff:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0104:  ldarg.0
    IL_0105:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_010b:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_0110:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0115:  nop
    IL_0116:  br         IL_026f

    IL_011b:  ldarg.2
    IL_011c:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0121:  ldarg.0
    IL_0122:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0128:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_012d:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0132:  nop
    IL_0133:  br         IL_026f

    IL_0138:  ldarg.2
    IL_0139:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_013e:  ldarg.0
    IL_013f:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0145:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_014a:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_014f:  nop
    IL_0150:  br         IL_026f

    IL_0155:  ldarg.2
    IL_0156:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_015b:  ldarg.0
    IL_015c:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0162:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_0167:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_016c:  nop
    IL_016d:  br         IL_026f

    IL_0172:  ldarg.2
    IL_0173:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0178:  ldarg.0
    IL_0179:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_017f:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_0184:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0189:  nop
    IL_018a:  br         IL_026f

    IL_018f:  ldarg.2
    IL_0190:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0195:  ldarg.0
    IL_0196:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_019c:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_01a1:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_01a6:  nop
    IL_01a7:  br         IL_026f

    IL_01ac:  ldarg.2
    IL_01ad:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_01b2:  ldarg.0
    IL_01b3:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_01b9:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_01be:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_01c3:  nop
    IL_01c4:  br         IL_026f

    IL_01c9:  ldarg.2
    IL_01ca:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_01cf:  ldarg.0
    IL_01d0:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_01d6:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_01db:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_01e0:  nop
    IL_01e1:  br         IL_026f

    IL_01e6:  ldarg.2
    IL_01e7:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_01ec:  ldarg.0
    IL_01ed:  ldftn      instance void MyCalculatorv1.MainWindow::Result_click(object,
                                                                               class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_01f3:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_01f8:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_01fd:  nop
    IL_01fe:  br.s       IL_026f

    IL_0200:  ldarg.2
    IL_0201:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0206:  ldarg.0
    IL_0207:  ldftn      instance void MyCalculatorv1.MainWindow::Button_Click_1(object,
                                                                                 class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_020d:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_0212:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0217:  nop
    IL_0218:  br.s       IL_026f

    IL_021a:  ldarg.2
    IL_021b:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0220:  ldarg.0
    IL_0221:  ldftn      instance void MyCalculatorv1.MainWindow::Off_Click_1(object,
                                                                              class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0227:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_022c:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0231:  nop
    IL_0232:  br.s       IL_026f

    IL_0234:  ldarg.2
    IL_0235:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_023a:  ldarg.0
    IL_023b:  ldftn      instance void MyCalculatorv1.MainWindow::Del_Click(object,
                                                                            class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_0241:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_0246:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_024b:  nop
    IL_024c:  br.s       IL_026f

    IL_024e:  ldarg.2
    IL_024f:  castclass  [PresentationFramework]System.Windows.Controls.Button
    IL_0254:  ldarg.0
    IL_0255:  ldftn      instance void MyCalculatorv1.MainWindow::R_Click(object,
                                                                          class [PresentationCore]System.Windows.RoutedEventArgs)
    IL_025b:  newobj     instance void [PresentationCore]System.Windows.RoutedEventHandler::.ctor(object,
                                                                                                  native int)
    IL_0260:  callvirt   instance void [PresentationFramework]System.Windows.Controls.Primitives.ButtonBase::add_Click(class [PresentationCore]System.Windows.RoutedEventHandler)
    IL_0265:  nop
    IL_0266:  br.s       IL_026f

    IL_0268:  ldarg.0
    IL_0269:  ldc.i4.1
    IL_026a:  stfld      bool MyCalculatorv1.MainWindow::_contentLoaded
    IL_026f:  ret
  } // end of method MainWindow::System.Windows.Markup.IComponentConnector.Connect

} // end of class MyCalculatorv1.MainWindow

.class private auto ansi beforefieldinit MyCalculatorv1.Properties.Resources
       extends [mscorlib]System.Object
{
  .custom instance void [System]System.CodeDom.Compiler.GeneratedCodeAttribute::.ctor(string,
                                                                                      string) = ( 01 00 33 53 79 73 74 65 6D 2E 52 65 73 6F 75 72   // ..3System.Resour
                                                                                                  63 65 73 2E 54 6F 6F 6C 73 2E 53 74 72 6F 6E 67   // ces.Tools.Strong
                                                                                                  6C 79 54 79 70 65 64 52 65 73 6F 75 72 63 65 42   // lyTypedResourceB
                                                                                                  75 69 6C 64 65 72 07 34 2E 30 2E 30 2E 30 00 00 ) // uilder.4.0.0.0..
  .custom instance void [mscorlib]System.Diagnostics.DebuggerNonUserCodeAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .field private static class [mscorlib]System.Resources.ResourceManager resourceMan
  .field private static class [mscorlib]System.Globalization.CultureInfo resourceCulture
  .method assembly hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       9 (0x9)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  nop
    IL_0008:  ret
  } // end of method Resources::.ctor

  .method assembly hidebysig specialname static 
          class [mscorlib]System.Resources.ResourceManager 
          get_ResourceManager() cil managed
  {
    // Code size       57 (0x39)
    .maxstack  2
    .locals init (bool V_0,
             class [mscorlib]System.Resources.ResourceManager V_1,
             class [mscorlib]System.Resources.ResourceManager V_2)
    IL_0000:  nop
    IL_0001:  ldsfld     class [mscorlib]System.Resources.ResourceManager MyCalculatorv1.Properties.Resources::resourceMan
    IL_0006:  ldnull
    IL_0007:  ceq
    IL_0009:  stloc.0
    IL_000a:  ldloc.0
    IL_000b:  brfalse.s  IL_002f

    IL_000d:  nop
    IL_000e:  ldstr      "MyCalculatorv1.Properties.Resources"
    IL_0013:  ldtoken    MyCalculatorv1.Properties.Resources
    IL_0018:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_001d:  callvirt   instance class [mscorlib]System.Reflection.Assembly [mscorlib]System.Type::get_Assembly()
    IL_0022:  newobj     instance void [mscorlib]System.Resources.ResourceManager::.ctor(string,
                                                                                         class [mscorlib]System.Reflection.Assembly)
    IL_0027:  stloc.1
    IL_0028:  ldloc.1
    IL_0029:  stsfld     class [mscorlib]System.Resources.ResourceManager MyCalculatorv1.Properties.Resources::resourceMan
    IL_002e:  nop
    IL_002f:  ldsfld     class [mscorlib]System.Resources.ResourceManager MyCalculatorv1.Properties.Resources::resourceMan
    IL_0034:  stloc.2
    IL_0035:  br.s       IL_0037

    IL_0037:  ldloc.2
    IL_0038:  ret
  } // end of method Resources::get_ResourceManager

  .method assembly hidebysig specialname static 
          class [mscorlib]System.Globalization.CultureInfo 
          get_Culture() cil managed
  {
    // Code size       11 (0xb)
    .maxstack  1
    .locals init (class [mscorlib]System.Globalization.CultureInfo V_0)
    IL_0000:  nop
    IL_0001:  ldsfld     class [mscorlib]System.Globalization.CultureInfo MyCalculatorv1.Properties.Resources::resourceCulture
    IL_0006:  stloc.0
    IL_0007:  br.s       IL_0009

    IL_0009:  ldloc.0
    IL_000a:  ret
  } // end of method Resources::get_Culture

  .method assembly hidebysig specialname static 
          void  set_Culture(class [mscorlib]System.Globalization.CultureInfo 'value') cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  stsfld     class [mscorlib]System.Globalization.CultureInfo MyCalculatorv1.Properties.Resources::resourceCulture
    IL_0007:  ret
  } // end of method Resources::set_Culture

  .property class [mscorlib]System.Resources.ResourceManager
          ResourceManager()
  {
    .custom instance void [System]System.ComponentModel.EditorBrowsableAttribute::.ctor(valuetype [System]System.ComponentModel.EditorBrowsableState) = ( 01 00 02 00 00 00 00 00 ) 
    .get class [mscorlib]System.Resources.ResourceManager MyCalculatorv1.Properties.Resources::get_ResourceManager()
  } // end of property Resources::ResourceManager
  .property class [mscorlib]System.Globalization.CultureInfo
          Culture()
  {
    .custom instance void [System]System.ComponentModel.EditorBrowsableAttribute::.ctor(valuetype [System]System.ComponentModel.EditorBrowsableState) = ( 01 00 02 00 00 00 00 00 ) 
    .get class [mscorlib]System.Globalization.CultureInfo MyCalculatorv1.Properties.Resources::get_Culture()
    .set void MyCalculatorv1.Properties.Resources::set_Culture(class [mscorlib]System.Globalization.CultureInfo)
  } // end of property Resources::Culture
} // end of class MyCalculatorv1.Properties.Resources

.class private auto ansi sealed beforefieldinit MyCalculatorv1.Properties.Settings
       extends [System]System.Configuration.ApplicationSettingsBase
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .custom instance void [System]System.CodeDom.Compiler.GeneratedCodeAttribute::.ctor(string,
                                                                                      string) = ( 01 00 4B 4D 69 63 72 6F 73 6F 66 74 2E 56 69 73   // ..KMicrosoft.Vis
                                                                                                  75 61 6C 53 74 75 64 69 6F 2E 45 64 69 74 6F 72   // ualStudio.Editor
                                                                                                  73 2E 53 65 74 74 69 6E 67 73 44 65 73 69 67 6E   // s.SettingsDesign
                                                                                                  65 72 2E 53 65 74 74 69 6E 67 73 53 69 6E 67 6C   // er.SettingsSingl
                                                                                                  65 46 69 6C 65 47 65 6E 65 72 61 74 6F 72 08 31   // eFileGenerator.1
                                                                                                  31 2E 30 2E 30 2E 30 00 00 )                      // 1.0.0.0..
  .field private static class MyCalculatorv1.Properties.Settings defaultInstance
  .method public hidebysig specialname static 
          class MyCalculatorv1.Properties.Settings 
          get_Default() cil managed
  {
    // Code size       11 (0xb)
    .maxstack  1
    .locals init (class MyCalculatorv1.Properties.Settings V_0)
    IL_0000:  nop
    IL_0001:  ldsfld     class MyCalculatorv1.Properties.Settings MyCalculatorv1.Properties.Settings::defaultInstance
    IL_0006:  stloc.0
    IL_0007:  br.s       IL_0009

    IL_0009:  ldloc.0
    IL_000a:  ret
  } // end of method Settings::get_Default

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [System]System.Configuration.ApplicationSettingsBase::.ctor()
    IL_0006:  nop
    IL_0007:  ret
  } // end of method Settings::.ctor

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       21 (0x15)
    .maxstack  8
    IL_0000:  newobj     instance void MyCalculatorv1.Properties.Settings::.ctor()
    IL_0005:  call       class [System]System.Configuration.SettingsBase [System]System.Configuration.SettingsBase::Synchronized(class [System]System.Configuration.SettingsBase)
    IL_000a:  castclass  MyCalculatorv1.Properties.Settings
    IL_000f:  stsfld     class MyCalculatorv1.Properties.Settings MyCalculatorv1.Properties.Settings::defaultInstance
    IL_0014:  ret
  } // end of method Settings::.cctor

  .property class MyCalculatorv1.Properties.Settings
          Default()
  {
    .get class MyCalculatorv1.Properties.Settings MyCalculatorv1.Properties.Settings::get_Default()
  } // end of property Settings::Default
} // end of class MyCalculatorv1.Properties.Settings


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file D:\DumpHomework\x86\mycalculator.res
