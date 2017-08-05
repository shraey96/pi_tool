<html>
<head>
    
      <link href="bootstrap-4.0.0-alpha.6-dist/css/bootstrap.css" rel="stylesheet">
      <script src="scripts/jquery-3.1.1.js"></script>
      <script src="scripts/tether.min.js"></script>
      <script src="bootstrap-4.0.0-alpha.6-dist/js/bootstrap.js"></script>
      <link href="css/login-form.css" type="text/css" rel="stylesheet">
    
    
    </head>

    <body>
      
<div class="login-page">
    <div class="form">
        <i>Machine Login</i>
    <form class="login-form" method="post" action="login.php">
        
        
      <input type="text" placeholder="ip address" name="ip" id="ip" />
      <input type="text" placeholder="username" name="uname" id="uname"/>
      <input type="password" placeholder="password" name="pass" id="pass"/>
      <input type="text" placeholder="community" name="comm" id="comm"/>
        
      <button name="login" onclick="login_verify()" type="button">login</button>
      
    </form>
    </div>
</div>
 
        

    
 </body>

    <script>
        
      
        
        //// Verify user login using AJAX from login_register_verify.php
function login_verify()     
{
            var ip = $('#ip').val();
            var uname = $('#uname').val();
            var pass = $('#pass').val();
            var comm = $('#comm').val();
    
        if(uname.length!=0 && pass.length!=0 && ip.length!=0 && comm.length!=0)
            {
        
        $.ajax
        ({
            
          method: "POST",
          url: "login2.php",
        dataType: 'json',
             error: function(data)
         {
              alert((data.responseText));
            
         },
          data: {function:"login",uname: uname, pass: pass, ip: ip, comm: comm},
          success: function(data)
            {   
                if(data.length==0)
                    {   
                        window.location.href = ("admin.php");
                    }
                else
                    {
                        alert(data)
                    }                
            }
        })
                
        }
            
        else
        {
            alert("Fields can't be empty!");
        }
        
        
}
        

    </script>
    
    
    
  

        
  

</html>