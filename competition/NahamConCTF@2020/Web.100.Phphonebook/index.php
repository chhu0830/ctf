<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Phphonebook</title>
    <link href="main.css" rel="stylesheet">
  </head>
  <body>
	<?php
		$file=$_GET['file'];
		if(!isset($file))
		{
			echo "Sorry! You are in /index.php/?file=";
		} else
		{
			include(str_replace('.php','',$_GET['file']).".php");
			die();
		}
	?>
	  	<p>The phonebook is located at <code>phphonebook.php</code></p>

<div style="position:fixed; bottom:1%; left:1%;">
<br><br><br><br>
<b> NOT CHALLENGE RELATED:</b><br>THANK YOU to INTIGRITI for supporting NahamCon and NahamCon CTF!
<p>
<img width=600px src="https://d24wuq6o951i2g.cloudfront.net/img/events/id/457/457748121/assets/f7da0d718eb77c83f5cb6221a06a2f45.inti.png">
</p>
</div>

  </body>
 </html>