<!DOCTYPE html>
<html lang="en">

<?php
    session_start();
      if(!isset($_SESSION['ip']))
    {
         header("Location: login.php");  //// if admin is not logged in, redirect to 'login.php;
    }
    
    ?>
    
    
     <head>

    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, shrink-to-fit=no, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

      <link href="bootstrap-4.0.0-alpha.6-dist/css/bootstrap.css" rel="stylesheet">
      <script src="scripts/jquery-3.1.1.js"></script>
      <script src="scripts/tether.min.js"></script>
      <script src="bootstrap-4.0.0-alpha.6-dist/js/bootstrap.js"></script>
  
      
      <link rel="stylesheet" href="css/style.css" type="text/css">
      <script src="scripts/highcharts.js"></script>
      <script src="scripts/theme.js"></script>
</head>
    

    


<body>

    
    
    
    <div id="wrapper">

     
        <nav class="navbar navbar-default navbar-fixed-top" id="header"> 
      <div class="container-fluid">
        <div class="row">
          <div class="col-md-12">
              <table>
                       <tr>
                           
      <td>  <img src="icons/icons8-Raspberry%20Pi-96.png" style="width:60px; height: 60px; margin-bottom:30px;" >  <h1 style="display:inline">Pi Monitor</h1></td> 
           
             <td style="padding-left:600px">        
                     <p id="systemCon"></p>
                     <p id="stat" style="margin-top:-15px;"></p>
                 <form method="post" style="margin-top:-10px;">
                      <button id="logout" name="logout">Logout</button>
                     </form>
                      </td>
                  </tr>
                </table>
          </div>
        </div>
      </div>
        </nav>
        
        <?php
        if(isset($_POST['logout']))
{  
        unset($_SESSION['ip']);
        unset($_SESSION['uname']);
        unset($_SESSION['pass']);
        unset($_SESSION['comm']);
        session_destroy();
        header("Location: login.php");
}
        
        
        ?>
        
        
        
        
        
        <!-- Page Content -->
        
        
        <!----- List of dropdowns on main screen -->
        <div id="page-content-wrapper" style="margin-top:120px;">
            <div class="container-fluid">
                <div class="row">
                  
         
       <div class="dropdown col-md-4">
  <a class="btn btn-primary btn-lg dropdown-toggle" id="dropdownMenuLink" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"><img src="icons/icons8-Workstation-48.png" width="25" height="25">
    Hardware Stats
  </a>

  <div class="dropdown-menu" aria-labelledby="dropdownMenuLink">
    <a class="dropdown-item" id="cpu_util"> CPU Utilization </a> 
    <a class="dropdown-item" id="ram_util" >RAM Utilization </a>
    <a class="dropdown-item" id="disk_util">Disk Utilization </a>
  </div>
</div>

   <div class="dropdown col-md-4">
  <a class="btn btn-success btn-lg dropdown-toggle" id="dropdownMenuLink" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"><img src="icons/icons8-Application%20Shield-50.png" width="25" height="25">
    Software Stats
  </a>

  <div class="dropdown-menu" aria-labelledby="dropdownMenuLink">
        <a class="dropdown-item" id="proc_util">Running Process </a>
        <a class="dropdown-item" id="service_util">Service Status </a> 
        <a class="dropdown-item" id="syslog_util">SysLog </a>
        <a class="dropdown-item" id="apachealog_util">Apache2 Access Logs </a>
        <a class="dropdown-item" id="apacheelog_util">Apache2 Error Logs </a>
        <a class="dropdown-item" id="mysqllog_util">MYSQL Logs </a>
        <a class="dropdown-item" id="mysqlelog_util">MYSQL Error Logs </a>
      
        <div id="dynamicLogs"></div> 
   
  </div>
</div>
                        
                        
   <div class="dropdown col-md-4">
  <a class="btn btn-danger btn-lg dropdown-toggle" id="dropdownMenuLink" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"><img src="icons/icons8-Wired%20Network-50.png"  width="25" height="25">
    Network Stats
  </a>

  <div class="dropdown-menu" aria-labelledby="dropdownMenuLink">
     <a class="dropdown-item" id="net_util">Network Bandwidth </a>
      
      <!--
    <a class="dropdown-item" id="activeports_util"> <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>Active Connections </a>

-->
  </div>
</div>
             

                    </div>
                        
                        <div class="row">
                        <div class="col-md-12">
                        
                            <!----- Graphs, dynamically generated logs, disk progress bars, server stats -->
                            
                            
                        <div id="logStuff"></div>
                        <div id="serverStats" style=""></div><br>
                        <div id="graphs"></div>  
                            
                        

                            
                            
                          <div id="diskProg" style="display:none;"><h3><u>% Free Space</u></h3>                             
                            </div>
                
                        
              
                    </div>
                </div>
            </div>
        </div>
        
  
        
        
        
        
        <!-- /#page-content-wrapper -->

    </div>
    <!-- /#wrapper -->


  
    

    
    
    <!----- Machine password verfiy (for SSH) Modal -->
    
    <div class="modal fade" id="verifyModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLongTitle" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="exampleModalLongTitle">Enter password for <p id='machineIP' style="display:inline"></p>: </h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
       <form method="post" class="register">
      
      <input type="password" name="vpass" id="vpass" placeholder="machine password"><br>
      <button value="login" type="button" id="machineLogin">Login</button>
    
    </form>
          
          
         
      </div>
      </div>
  </div>
</div> 
    

    
    <!-----Admin verify password Modal -->
    
        <div class="modal fade" id="adminVerify" tabindex="-1" role="dialog" aria-labelledby="exampleModalLongTitle" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="exampleModalLongTitle">Enter password for <p id='machineIP' style="display:inline"></p>: </h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
       <form method="post" class="register">
      <input type="password" name="apass" id="apass" placeholder="admin password"><br>
      <button value="login" type="button" id="adminVerifyButton">Verify</button>
    
    </form>
          
          
         
      </div>
      </div>
  </div>
</div> 
    
    <!--- Updation/Delet Modal -->
    
          


    
<script src="scripts/script1.js"></script>
</body>

</html>
