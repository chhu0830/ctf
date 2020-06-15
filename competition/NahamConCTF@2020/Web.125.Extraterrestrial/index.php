<?php

// Make sure we can fetch external entities.
// @see http://nl1.php.net/manual/en/function.libxml-disable-entity-loader.php
libxml_disable_entity_loader(false);

// Catch any and all libxml errors
// @see http://nl1.php.net/manual/en/function.libxml-use-internal-errors.php
libxml_use_internal_errors(false);

// Create a new xml parser.
// @see http://nl1.php.net/manual/en/function.xml-parser-create.php
$parser = xml_parser_create('UTF-8');

// A list of gathered external entities and their contents.
$externalEntities = array();

function externalEntityRefHandler(
    $parser,
    $openEntityNames,
    $base,
    $systemId,
    $publicId
) {
    global $externalEntities;

    if (!empty($systemId)) {
        $externalEntities[$openEntityNames] = @file_get_contents($systemId);
    }

    return (integer) (
        !empty($publicId)
        || !empty($externalEntities[$openEntityNames])
    );
}

xml_set_external_entity_ref_handler($parser, "externalEntityRefHandler");

?>

<!DOCTYPE html>

<html>
    <head>
        <title>Extraterrestrial</title>
        <meta charset="utf-8">
        <style>
            html{
                background-color: #50C878;
            }
            * {
                text-align:center;
            }
            pre, textarea {
                text-align:left;
            }
            body{
                width: 80%;
                padding: 10%;
                margin-left: auto;
                margin-right: auto;
                background-color: rgba(255,255,255,0.4)
            }
        </style>
    </head>
    <body>
        <h1> Extraterrestrial </h1>

        <p>
            <strong>We're doing a study on external life.</strong>
        </p>
        <p>
            If you find any alien life forms, please inform us using the form below.
        </p>
        <form method="POST" action="#">
            <textarea name="message" rows="10" cols="70"></textarea>
            <br><br>
            <input type="submit" value="Submit">
        </form>


<?php

if ( isset($_POST['message']) ){
    echo("<pre>");
    $xml = $_POST['message'];
        // Parse the XML.
    if (xml_parse($parser, $xml, true) === 1) {
        // Success.
        var_dump($externalEntities);
        
    } else {
        echo(xml_error_string ( xml_get_error_code ( $parser )) );

    }
    echo("</pre>");
}

// @see http://nl1.php.net/manual/en/function.xml-parser-free.php
xml_parser_free($parser);

?>

<div style="position:fixed; bottom:1%; right:1%;">
<br><br><br><br>
<b> NOT CHALLENGE RELATED:</b><br>THANK YOU to eLearnSecurity for supporting NahamCon and NahamCon CTF!
<p>
<img width=600px src="https://d24wuq6o951i2g.cloudfront.net/img/events/id/457/457693589/assets/d12.eLS_color-plat.png">
</p>
</div>
    </body>
</html>