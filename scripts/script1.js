////////variables and arrays/arrayObjects to be used in this script /////

var globalData = [];

var CPU_usage = {CPU: [], usage: []};
var RAM = {used_ram: [], used_swap: []}
var network = {interface: [],ip: [], stat: [], rb: [], tb: []};
var services = {service_name:[], service_status:[]};
var process = {pid:[], cpu:[], cmd:[]};
var disk  ={filesystem:[], used:[]};
var logs;
var logs2;
var ajaxTimer;
var reDrawTimer;
var mailTimer;
var ajax_request;
var functionLog;
var pass;

var oldJSON;
var currentJSON;

///////// onclick events of each dropdown item//////////

document.getElementById('ram_util').onclick = function(){
     usageCall("showRAM");
    $('#logStuff').html("");
    // $('#graphs').show();
     $('#diskProg').hide();
     drawChart()
}
document.getElementById('disk_util').onclick = function(){
    usageCall("showDisk");
    $('#logStuff').html("");
    //$('#diskProg').show();
    $('#graphs').hide();
}
document.getElementById('net_util').onclick = function(){
    usageCall("showNet");
    $('#logStuff').html("");
    $('#diskProg').hide();
    $('#graphs').hide();
    drawChart()
}
document.getElementById('service_util').onclick = function(){
   usageCall("showService")
    $('#logStuff').html("");
    $('#diskProg').hide();
    $('#graphs').hide();
}
document.getElementById('cpu_util').onclick = function(){
    usageCall("showCPU");
    $('#logStuff').html("");
    $('#diskProg').hide();
    drawChart();
}
/*
document.getElementById('activeports_util').onclick = function(){
    usageCall("showActPorts");
    $('#logStuff').html("");
    $('#diskProg').hide();
    $('#graphs').hide()
}
*/

document.getElementById('syslog_util').onclick = function(){
    usageCall("SysLogs");
    $('#diskProg').hide();
    $('#graphs').hide();
}
document.getElementById('apachealog_util').onclick = function(){
    usageCall("ApacheAccessLogs");
    $('#diskProg').hide();
    $('#graphs').hide();
}
document.getElementById('apacheelog_util').onclick = function(){
    usageCall("ApacheErrorLogs");
    $('#diskProg').hide();
    $('#graphs').hide();
}
document.getElementById('mysqllog_util').onclick = function(){
    usageCall("MYSQLLogs");
    $('#diskProg').hide();
    $('#graphs').hide();
}
document.getElementById('mysqlelog_util').onclick = function(){
    usageCall("MYSQLErrorLogs");
    $('#diskProg').hide();
    $('#graphs').hide();
}



document.getElementById('proc_util').onclick = function(){
     usageCall("showProc");
     $('#logStuff').html("");
     $('#diskProg').hide();
     $('#graphs').hide();
}

/////function to progressbar(s) with disk usage /////

function updateDiskProgress()
{   
    ///hide all progress bars at first///

$('#diskProg p').html("")

    
    ////progressbar colors. Color will be chosen depending on %Free space////
     var classGreen = "progress-bar progress-bar-striped bg-success";
     var classBlue = "progress-bar progress-bar-striped bg-info";
     var classOrange = "progress-bar progress-bar-striped bg-warning";
     var classRed = "progress-bar progress-bar-striped bg-danger";

    
    for(i=0; i<(disk.filesystem.length); i++)
       { console.log("updating disk graphs...");
        $('#disk'+i).show()
        percentDisk = (disk.used[i]);
        percentDisk = percentDisk.replace("%", "");
        if(percentDisk==100)
            {
               
                $('#disk'+(i)).css("width", ((100 - 1)+"%"));
            }
         else
             {
                 $('#disk'+(i)).css("width", ((100 - percentDisk)+"%"));
             }
         $('#disk'+ (i)).html((100 - (percentDisk))+"%");
        
         if((100-percentDisk)>=75)
             {   $('#disk'+(i)).removeClass();
                 $('#disk'+(i)).addClass(classGreen);                
             }
        else if((100-percentDisk)>=50 && (100-percentDisk)<75)
            {   $('#disk'+(i)).removeClass();
                $('#disk'+(i)).addClass(classBlue);                
             }
        else if((100-percentDisk)>=25 && (100-percentDisk)<50)
            {   $('#disk'+(i)).removeClass();
                $('#disk'+(i)).addClass(classOrange);                
             }
        else if((100-percentDisk)<25)
             {   $('#disk'+(i)).removeClass();
                 $('#disk'+(i)).addClass(classRed);                
             }
        else if((100-percentDisk)==0)
            {
                 $('#disk'+(i)).removeClass();
                 $('#disk'+(i)).addClass(classRed); 
            }
      }
    
      for(i=(disk.filesystem.length)-1;i>=0;i--)
        
        {$('#filesys'+i).html(disk.filesystem[i]);}
   
    
    
}





////////////////////////////////////// GRAPHS ////////////////////////////////////////////////////////////////////////////


////create a chart(highcharts.js). drawChart() function is called only on click events of Network Bandwidth, CPU usage, RAM usage.
var myChart;

        function drawChart()
        {
        
        myChart = Highcharts.chart('graphs', {
        chart: {
            type: 'line'
        },
           credits: {
           enabled: false
       },
         xAxis: {
        title: {
            text: 'Time (in seconds)'
        }
         },
         yAxis: {
        title: {
            text: ''
        }
         },    
        title: {
            text: ''
                },
            
        series: [{
            name: '',
            data: [],
            showInLegend: false,
        },
        {
            name: '',
            data: [],
            showInLegend: false,
        },
        {
            name: '',
            data: [],
             showInLegend: false,
        },
                 
        {
            name: '',
            data: [],
             showInLegend: false,
        },
        {
            name: '',
            data: [],
             showInLegend: false,
        },
        {
            name: '',
            data: [],
             showInLegend: false,
        }
                
        ]
    });
            
  }





//////Update chart/graph with ajax loaded data////

function updateChart(util)
{   
   
   clearInterval(reDrawTimer) ////clear timer that was set for updating chart
    
    $('#graphs').show(); ///show graphs canvas
            switch (util)
                {
                    
                case "cpu" :
                clearInterval(reDrawTimer);
                myChart.yAxis[0].update({title:{text:"CPU usage (%)"}}) ;  ////set chart/graph yAxis title 
                myChart.setTitle({text: "CPU Usage"}); ///
                    
                    ////loop through CPU_usage.CPU array and update each point from that array
                for(i=0; i<CPU_usage.CPU.length;i++)
                   {
                   myChart.series[i].update({showInLegend:null});
                   myChart.series[i].update({name: "Core"+i});   
                   myChart.series[i].addPoint(CPU_usage.usage[i])
                   } 
                    
             
                break;
                    
                    
                    
                case "ram" :
                    myChart.yAxis[0].update({title:{text:"RAM usage (MB)"}});
                    clearInterval(reDrawTimer);
                    myChart.setTitle({text: "Memory Usage"});
                    myChart.series[0].update({showInLegend:null});
                    myChart.series[1].update({showInLegend:null});
                    myChart.series[0].update({name:"Used RAM"});
                    myChart.series[1].update({name:"Used SWAP"});
                    myChart.series[0].addPoint(RAM.used_ram[0]*1000);
                    myChart.series[1].addPoint(RAM.used_swap[0]*1000);
                    break;
                    
                    
                   ////case for network interface(1) 
                case "i0" :
                    //console.log(network.tb)
                    myChart.yAxis[0].update({title:{text: "Interface " + network.interface[0] + " usage (KB/s)"}});
                    reDrawTimer = setInterval(function(){updateChart(util)},2000);  ///update chart every 2 seconds
                    myChart.series[0].update({showInLegend:null});
                    myChart.series[1].update({showInLegend:null});
                    myChart.series[0].update({name:"RX Bytes " + network.interface[0]});
                    myChart.series[1].update({name:"TX Bytes " + network.interface[0]});
                    myChart.series[0].addPoint(network.rb[0]);
                    myChart.series[1].addPoint(network.tb[0]);
                    break;
                    
                   ////case for network interface(2) 
                 case "i1" :
                    myChart.yAxis[0].update({title:{text: "Interface " + network.interface[1] + " usage (KB/s)"}});
                    reDrawTimer = setInterval(function(){updateChart(util)},2000);  ///update chart every 2 seconds
                    myChart.series[0].update({showInLegend:null});
                    myChart.series[1].update({showInLegend:null});
                    myChart.series[0].update({name:"RX Bytes " + network.interface[1]});
                    myChart.series[1].update({name:"TX Bytes " + network.interface[1]});
                    myChart.series[0].addPoint(network.rb[1]);
                    myChart.series[1].addPoint(network.tb[1]);
                    break;  
                    
                   ////case for network interface(3) 
                 case "i2" :
                    myChart.yAxis[0].update({title:{text: "Interface " + network.interface[2] + " usage (KB/s)"}});
                    reDrawTimer = setInterval(function(){updateChart(util)},2000);  ///update chart every 2 seconds
                    myChart.series[0].update({showInLegend:null});
                    myChart.series[1].update({showInLegend:null});
                    myChart.series[0].update({name:"RX Bytes " + network.interface[2]});
                    myChart.series[1].update({name:"TX Bytes " + network.interface[2]});
                    myChart.series[0].addPoint(network.rb[2]);
                    myChart.series[1].addPoint(network.tb[2]);
                    break;  
                    
           
                    
            }
  }




///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////





//// Main AJAX CALL FUNCTION to "ssh.php" 
//// This function will be called every x seconds, depending on the dropdown item clicked.

 function usage(functionName, control) {
     
    
     
     
     
     var displayString; 
     clearTimeout(ajaxTimer);
     console.log(functionName);
     timer = setTimer(functionName);  ///get timer value for each different function name
     console.log("Timer: " + timer) 
    
     
     ///AJAX call to ssh.php with following data parameters.
    ajax_request = $.ajax
     ({
          method: "POST",
          url: "ssh.php",
          dataType: 'json',
          cache: false,
          data: {functionexe : functionName, control: control, adminpass:pass, lines: "lines"},    ///key:value
            ///functionexe is main data parameter to be passed to ssh.php. 
        /// other data parameteres may/may not be required. Depends on each case in functionName
         
         error: function(e)
         {
              console.log("Errror");
              document.getElementById("serverStats").innerHTML = e + "There was some network problem...";
              
             
         },
          success: function(data)
         {   
             ajaxTimer = setTimeout(function(){usage(functionName)},timer);
     
             console.log("globalData");
             
     
             
               switch (functionName)
             {
                       
         case 'showRAM':
              ///JSON         
             console.log("/////// RAM Stats: //////");
             console.log(JSON.stringify(data))          
                       
             displayString =  "RAM Usage: <br><table class='table'><tbody><tr><td><b>SWAP</b><br>Total SWAP: " +  (data.tswap)  + " GB<br>Available SWAP: " + data.aswap + " GB<br>Used SWAP: " + data.uswap + " GB</td><td><b>RAM</b><br>Total RAM: " + parseFloat((data.tram).toFixed(3)) + " GB<br>Available RAM: " + parseFloat((data.fram).toFixed(3)) + " GB<br>Used RAM: " + parseFloat((data.uram).toFixed(3)) + " GB</td><td><b>Other</b><br>RAM Buffered: " + parseFloat((data.buff).toFixed(3)) + " GB<br>Cached Memory: " +parseFloat((data.cach).toFixed(3)) +" GB</td></tbody></table>";  
                       
                    ///split globalData and push to array/object
                       
                RAM.used_swap.push(data.uswap);
                RAM.used_ram.push(data.uram);       
                       
               // $('#graphs').show();
                updateChart("ram");
                
                RAM.used_swap.length=0;
                RAM.used_ram.length=0;       
                      
             break;
        
                       
                       
                       
         case 'showDisk':
            ///JSON
            disk.filesystem.length=0;
            disk.used.length=0;
                    
                    console.log(JSON.stringify(data));
                    var string="";
                       
            //every 4th index is partion(filesystem), starting with 0           
             console.log("/////// Disk Stats: //////");
                       
                       console.log((JSON.stringify(data)))
            displayString = "Disk Usage: <br><table class='table' border='1'>" +
               "<thead class='thead-inverse'><tr><th>Filesystem</th><th>Size</th><th>Used</th><th>Available</th></thead><tbody>" 
                       
                   for(i=0; i<data.length; i++)
                    {   
                       
                            displayString+= "<tr><td>" + data[i].filesystem + "</td><td>" + data[i].size + "</td><td>"+ data[i].used + "</td><td>" + data[i].avail + "</td></tr>";
                       
                        
                            disk.filesystem.push(data[i].filesystem);
                            disk.used.push(data[i].usep);
                        
                        string += '<p id="filesys'+i+'"></p> <div class="progress"><div class="progress-bar .progress-bar-striped" id="disk'+i+'" style=""></div></div>';
                    }
                    
                    
                 $('#diskProg').html(string);
                
                 displayString+="</tbody></table>";  
                $('#diskProg').show();
                 updateDiskProgress()
                       
             break;
                       
                       
                       
         case 'showNet':
            
                       
            network.rb.length=0;
            network.tb.length=0;
              
                       globalData = data.slice();
                       
            console.log("/////// Net Stats: //////");
                
             var properties = (globalData.length)/5;       
                       
                         ///split globalData and push to array/object
                       
          for(i=0; i<globalData.length; i++)
              {
              
                  
                  if(i>=0 && i<properties)
                      {                      
                      network.interface.push(globalData[i]);
                      }
                 else if(i>=properties && i<properties*2)
                      {                            
                         network.ip.push(globalData[i]);
                      }
                 
                 else if(i>=properties*2 && i<properties*3)
                      {      
                         network.stat.push(globalData[i]);
                      }
                  else if(i>=properties*3 && i<properties*4)
                      {    
                         network.rb.push(globalData[i]/1000);
                      }
                  else if(i>=properties*4 && i<properties*45)
                      {   
                         network.tb.push(globalData[i]/1000);
                      }
                      
                   
              }
         
                    
                       
                          displayString = "Network Stats: <br><table class='table table-striped' border='1'>" +
               "<thead class='thead-inverse'><tr><th>Interface</th><th>IP Address</th><th>Status</th><th>Bandwidth</th></thead><tbody>" 
                       
                           for(i=0; i<properties; i++)
                    {
                        displayString+= '<tr><td>' + network.interface[i]  + "</td><td>" + network.ip[i] + "</td><td>" +                    network.stat[i] + '</td><td><button id="interface'+i+'" onclick=updateChart("i'+i+'")>' + 'view</button> Rx: '+ formatBytes(network.rb[i]) + '/s Tx: ' + formatBytes(network.tb[i]) + '/s</td></tr>';
                             
                         }
                
                 displayString+="</tbody></table><br>";  
                       
                    
                       console.log(globalData);
                    
                break;
                
            
                       
         case 'showService':
              
                  console.log(JSON.stringify(data));
                  services.service_name.length=0;
                  services.service_status.length=0;
                       console.log("/////// Service Stats: //////");
                       
                       for(i=0;i<(data.length);i++)
                           {
                               services.service_name.push(data[i].service);
                               services.service_status.push(data[i].status);
                           }  
                  
           displayString = "Running Services: <br><table class='table table-striped' border='1'><thead class='thead-inverse'><tr><th>Service</th><th>Status</th><th>Controls</th></thead><tbody>";
                         
                       
                     
                     var color;
                       
                       for(i=0;i<(services.service_name.length);i++)
                           {    
                               if(services.service_status[i]=="running..." || services.service_status[i]=="Running")
                                   {
                                       color="lawngreen";
                                   }
                               else
                                   {
                                       color="red";
                                   }
                               
                               ///create start,stop and restart button for ech service
                               displayString += '<tr><td>' + services.service_name[i] + '</td><td style=color:'+color+'>' + services.service_status[i] + '</td><td><button onclick=serviceControl(services.service_name['+i+'],"start")>Start</button><button onclick=serviceControl(services.service_name['+i+'],"stop")>Stop</button><button onclick=serviceControl(services.service_name['+i+'],"restart")>Restart</button></td></tr>';
                           }
                       
                           
                       
                            displayString +=  '</tbody></table><button onclick=usageCall("showServiceX")>Refresh</button>';
                         
                       
                       

                  break;
                   
                     //  onclick=serviceControl('killProc',process.pid["+i+"])
                       
                       
         case 'showCPU':
               
                        CPU_usage.CPU.length=0;
                      CPU_usage.usage.length=0;
                     
                    console.log("//////// CPU Stats: //////");     
                     globalData = data.slice(); 
                     console.log(globalData);
                       
                       displayString = "CPU Usage: <br><p>Number of Cores: " + globalData.length + "</p>";
                       for(i=0; i<globalData.length; i++)
                           {
                               displayString+= "CPU" + i + " usage: " + globalData[i] + "%" + "<br>";
                               CPU_usage.CPU.push(i);
                               CPU_usage.usage.push(parseInt(globalData[i]))
                           }
                       
                       
                      updateChart("cpu");
                     
     
            // $('#graphs').show();
                       
            break;
                       
                       
     case 'showProc':
                process.pid.length=0;
                process.cpu.length=0;
                process.cmd.length=0;
                
        displayString = "Running Processes: <br><table class='table' border='1'>" +
               "<thead class='thead-inverse'><tr><th>Process ID(PID)</th><th>CPU %</th><th>Command</th><th>Control</th></thead><tbody>";
                       
        for(i=3;i<(data.length);i=i+3)
        {
            process.pid.push(data[i].pid);
            process.cpu.push(data[i].cpu);
            process.cmd.push(data[i].cmd);
        }
        
                    for(i=0; i<process.pid.length;i++)
                        {
                             displayString +="<tr><td>" + process.pid[i] + "</td><td>" + process.cpu[i] + "</td><td>"+ process.cmd[i] + "</td><td><button onclick=serviceControl('killProc',process.cmd["+i+"])> Kill Process</button></td</tr>";
                        }
                       
              displayString+="</tbody></table>";           
                     
           break;  
                       
                       
                       
         case 'showActPorts':
         
               console.log("//////// Activeports Stats: //////");         
                       
                displayString = "Active Connections: <br><table class='table table-striped' border='1'>" +
               "<thead class='thead-inverse'><tr><th>PID/ProgramName</th><th>Local Address:Port</th></thead><tbody>"         
                       
                        for(i=0; i<globalData.length; i=i+4)
                    { displayString+= "<tr><td>" + globalData[i] + "</td><td>" + globalData[i+1] + "</td></tr>";}
                       
                 
                
                 displayString+="</tbody></table>";  
            break;
                 
    
                     
         case 'MYSQLErrorLogs':              
         case 'MYSQLLogs':
         case 'SysLogs':
         case 'ApacheErrorLogs':
         case 'ApacheAccessLogs':              
              
              globalData = data.slice();
              console.log(data)
              functionLog = functionName;         
               
          //  $('#serverStats').css("overflow-y", "scroll");        
          //  $('#serverStats').css("height", "5%");            
         //   displayStringLog = "<br><input type='radio' name='log' value='head'>Top Part  " + "<input type='radio' name='log' value='tail' checked='checked'>Bottom Part<br>" + "<input type='number' placeholder='Number of lines to display' id='numberOfLines'><button onclick=logCheck()>Go</button><br>";      
            var displayString="";           
           var displayStringLog = "<h3>" + functionLog + "</h3><input type='text' placeholder='Search keyword(s)...' id='filter'><button onclick=filterLogs()>Filter</button><button onclick=showOrgLogs()>Reset</button><p>";
                       
            displayString+= "<table class='table table-striped' border='1'>" + "<thead class='thead-inverse'><tr><th></th></thead><tbody>"
                       
                       for(i=0; i<globalData.length;i++)
                         { 
                             displayString+=  "<tr><td>" + globalData[i] + "</td></tr>" ; 
                         }
                        displayString+="</tbody></table>";  
                            logs = globalData.slice();
                            logs2 = globalData.slice();
                       
            $('#logStuff').html(displayStringLog);
             break;
                 }
            
            // $('#logStuff').html("");
             
             document.getElementById("serverStats").innerHTML = displayString;
             console.log("refreshing...");
             
             data.length=0;
             globalData.length=0;
             
         }
     });
     
 }



function usageCall(functionName)
{  
    if(typeof(ajax_request) !== 'undefined')
    {    ajax_request.abort();   }
    $('#graphs').hide();
    $('#diskProg').hide();
    document.getElementById("serverStats").innerHTML = "";
    $('#serverStats').html("<img src='ajax-loader.gif' id='gif_img'>");
    globalData.length=0;
    console.log(functionName);
    clearInterval(reDrawTimer)
    usage(functionName);
}



///// functions to view and grep(filter) logsse


function logCheck()
{
var control= $('input[name=log]:checked').val();
var lines = $('#numberOfLines').val();
var displayStringLog;   
  
    
    if(control=="tail" && lines<1000)
     {
         logs2.length=0;
       for(i=0;i<lines;i++)
       {
         displayStringLog += "<p>" + logs[i] + "<p>";
         logs2[i] = logs[i];

       }
         logs=logs2.slice();
      
       $('#serverStats').html(displayStringLog);
            
     }
    
    else
   {   
       if(lines.length==0) {alert("Enter number of lines to query for logs!");}
       else
   { 
       logs.length=0;
       $.ajax
                            ({
                             method: "POST",
                             url: "ssh.php",
                             dataType: 'json',
                             data: {functionexe : functionLog, control: control, lines: lines},   
        
         
                beforeSend: function()
                        {  $('#serverStats').html("<img src='ajax-loader.gif' id='gif_img'>"); },
                        
                        success: function(data)
                             { 
                                 for(i=0;i<data.length;i++)
                                 {
                                     displayStringLog += "<p>" + data[i] + "<p>";
                                 }
                                 logs = data.slice();
                                 
                                 $('#serverStats').html(displayStringLog)
                             }
        
                            });
   }
}
}



function filterLogs()
{
var keyword = $('#filter').val();
    $('#serverStats').html(""); 
    var displayString;
      displayString= "<table class='table table-striped' border='1'>" + "<thead class='thead-inverse'><tr><th></th></thead><tbody>"
                       
   
 $('#logStuff').html("<br><input type='radio' name='log' value='head'>Top Part  " + "<input type='radio' name='log' value='tail' checked='checked'>Bottom Part<br>" + "<input type='number' placeholder='Number of lines to display' id='numberOfLines'><button onclick=logCheck()>Go</button><br><h3>" + functionLog + "</h3><input type='text' placeholder='Search keyword(s)...' id='filter'><button onclick=filterLogs()>Filter</button><button onclick=showOrgLogs()>Reset</button>");
    
    $.each(logs, function(index, elem) {
       if (elem.match(keyword)) {
           displayString+= "<tr><td>" + elem + "</td></tr>";
        $('#serverStats').html(displayString);
       // filtered_logs.push(elem);
         }
        });
    
     displayString+="</tbody></table>";  
    

    /*
    for(i=0;i<filtered_logs.length;i++)
        {
          $('#serverStats').append("<p>" + elem + "</p>" + "<br>");  
        }
    filtered_logs.length=0;
    
    */
}


function showOrgLogs()
{
    $('#logStuff').html("<br><input type='radio' name='log' value='head'>Top Part  " + "<input type='radio' name='log' value='tail' checked='checked'>Bottom Part<br>" + "<input type='number' placeholder='Number of lines to display' id='numberOfLines'><button onclick=logCheck()>Go</button><br><h3>" + functionLog + "</h3><input type='text' placeholder='Search keyword(s)...' id='filter'><button onclick=filterLogs()>Filter</button><button onclick=showOrgLogs()>Reset</button>");
    $('#serverStats').html("");
     var displayString;
      displayString= "<table class='table table-striped' border='1'>" + "<thead class='thead-inverse'><tr><th></th></thead><tbody>"
      
    for(i=0;i<logs.length;i++)
    { displayString+= "<tr><td>" + logs[i] + "</td></tr>";
        $('#serverStats').html(displayString);
    }
    displayString+="</tbody></table>";
    //logs.length=0;
}






function serviceControl(functionName, control)
{     //if(functionName=="")
   clearTimeout(mailTimer);
    $.ajax
     ({
          method: "POST",
          url: "ssh.php",
          dataType: 'json',
          data: {functionexe : functionName, control: control},   
        
        success: function(data)
        {
            if(functionName=="killProc")
                {
                    functionName="showProc";
                }
            if(control=="start" || control=="stop" || control=="restart")
                {
                    functionName="showService";
                }
            alert(data);
            usageCall(functionName);
        }
    })
}




//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/// get current session and display on top right side of page
function getIPSession()
{
        clearTimeout(mailTimer);
       if(typeof(ajax_request) !== 'undefined')
    {    ajax_request.abort();   }
            
       $('#stat').html("");
       $('#serverStats').html("");
       $('#graphs').hide();
    
    
    $.ajax
        ({
            
          method: "POST",
          url: "verify.php",
          data: {functionN:"getIP"},
          dataType: 'json',
            success: function(data)
            {
              
 
                    $('#systemCon').html(data.ip + " (" + data.host + ")") ;
                
            }
            
        })
}
getIPSession();

///system online/offline /// 
///check if system is online or offline by calling SNMP function from php file
function systemCon()
{   $.ajax
     ({
          method: "POST",
          url: "ssh.php",
          dataType: 'json',
          data: {functionexe : "sysUp", control: "control"},   
          beforeSend: function()
        {//$('#stat').html("");
        },
        
        success: function(data)
        {   //console.log(data)
          //  alert(data)
            if(data==0)
            {$('#stat').html("<b style='color: green'>online</b>");}
            else
            {$('#stat').html("<b style='color: red'>offline</b>");}
        
        
    }})
}

systemCon()
setInterval(systemCon,5000);

///////////////////////////////////////////////////////////////






/// set timer for setinterval of usage() function
function setTimer(functionName)
{
    var timer;
    
    switch (functionName)
    {
        case "showNet":
        case "showCPU":
        case "showRAM":
        timer = 2000;
        break;
        case "showActPorts":
        case "showProc":
        timer = 5000;
        break;
        case "showService":
        timer = 3000000;
        break;
        default:
        timer = 3000000;
        break;
    }

return timer;
}
    



         
///// Array Edits  //////


function removeNonNumeric(str)
{   console.log("removed non numeric: ")
    console.log(str.replace(/[^0-9\.]/g, ''));
 
  return str.replace(/[^0-9\.]/g, '');
}


function removeSpecialChars(str)
{
     return str.replace(/(?!\w|\s)./g, '');
}

function formatBytes(bytes) 
{
    if(bytes < 1024) return bytes + " Bytes";
    else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KB";
    else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MB";
    else return(bytes / 1073741824).toFixed(3) + " GB";
}


/*
xyz();

function xyz()
{
$(".dropdown-menu .dropdown-item").click(function(e) {
   $(".dropdown-menu .dropdown-item").removeClass(".dropdown-item-item-success");
   //$(".dropdown-menu .dropdown-item a").unbind();
   $(e.target).addClass("dropdown-item-success");
});
}
*/


$(".ip_links").click(function(e) {
   $(".ip_links").removeClass("ip_links_selected");
   //$(e.target).unbind();

   $(e.target).addClass("ip_links_selected");
});

$('form input').on('keypress', function(e) {
    return e.which !== 13;
});