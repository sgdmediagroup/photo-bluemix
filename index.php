<?php
// use Composer autoloader
require 'vendor/autoload.php';

// load classes
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Silex\Application;
use ZendService\OpenStack\ObjectStorage;

// define configuration array
// ... for object storage service
$config["storage"] = array(
  'service' => array(
  ),
  'adapter' => array(
    'adapter' => 'Zend\Http\Client\Adapter\Curl',
    'curloptions' => array(CURLOPT_SSL_VERIFYPEER => false, CURLOPT_TIMEOUT => 6000),  
  )
);

// ... for HybridAuth
$config["hybridauth"]  = array(
  "base_url" => "http://photos.mybluemix.net/callback",
  "providers" => array (
  "Google" => array (
    "enabled" => true,
    "keys" => array (
      "id" => "YOUR_CLIENT_ID", 
      "secret" => "YOUR_CLIENT_SECRET" 
    ),
    "scope" => "https://www.googleapis.com/auth/userinfo.email"
)));

// use BlueMix VCAP_SERVICES environment 
if ($services = getenv("VCAP_SERVICES")) {
  $services_json = json_decode($services, true);
  $config["storage"]["service"]["url"] = $services_json["objectstorage"][0]["credentials"]["auth_uri"];
  $config["storage"]["service"]["user"] = $services_json["objectstorage"][0]["credentials"]["username"];
  $config["storage"]["service"]["key"] = $services_json["objectstorage"][0]["credentials"]["password"];
} else {
  throw new Exception('Not in Bluemix environment');
}

// start session
session_start();

// initialize HybridAuth client
$auth = new Hybrid_Auth($config["hybridauth"]);

// initialize Silex application
$app = new Application();

// register Twig template provider
$app->register(new Silex\Provider\TwigServiceProvider(), array(
  'twig.path' => __DIR__.'/views',
));

// register URL generator
$app->register(new Silex\Provider\UrlGeneratorServiceProvider());

// register authentication middleware
$authenticate = function (Request $request, Application $app) use ($config) {
  if (!isset($_SESSION['uid'])) {
    return $app->redirect($app["url_generator"]->generate('login'));
  } 
  $config["storage"]["service"]["url"] .= '/' . str_replace(array('@', '.'), '_', $_SESSION['uid']); 
  $app['os'] = new ObjectStorage(
    $config["storage"]["service"], 
    new Zend\Http\Client('', $config["storage"]["adapter"])
  );    
};

// index page handlers
$app->get('/', function () use ($app) {
  return $app->redirect($app["url_generator"]->generate('index'));
});

$app->get('/index', function () use ($app) {
  $containers = (array) $app['os']->listContainers();
  foreach ($containers as &$c) {
    $objects = json_decode($app['os']->listObjects($c['name']));
    foreach ($objects as &$o) {
      $o = (array) $o;
      $o['url'] = $app['os']->getObjectUrl($c['name'], $o['name']);
    }
    $c['objects'] = $objects;
  }
  return $app['twig']->render('index.twig', array(
    'uid' => $_SESSION['uid'], 
    'containers' => $containers
    ));
})
->before($authenticate)
->bind('index');

// file upload form
$app->get('/add', function () use ($app) {
  $containers = (array) $app['os']->listContainers();
  return $app['twig']->render('add.twig', array(
    'uid' => $_SESSION['uid'],   
    'containers' => $containers
  ));
})
->before($authenticate);

// file upload processor
// get and check uploaded file
// if valid, create container and add file
$app->post('/add', function (Request $request) use ($app) {
  $file = $request->files->get('file');
  $containerNew = $request->get('container-new');
  $containerExisting = $request->get('container');
  $container = (!empty($containerNew)) ? urldecode($containerNew) : urldecode($containerExisting);
  if ($file && $file->isValid()) {
    if (in_array($file->getClientMimeType(), array('image/gif', 'image/jpeg', 'image/png'))) {
      if (!empty($containerNew)) {
        $app['os']->createContainer($container);
      }
      $app['os']->setObject($container, $file->getClientOriginalName(), file_get_contents($file->getRealPath()));
    } else {
      throw new Exception('Invalid image format');
    }
  } else {
    throw new Exception('Invalid upload');
  }
  return $app->redirect($app["url_generator"]->generate('index'));    
})
->before($authenticate);

// delete handler
// if object provided, delete object
// if container provided, delete objects in container, then delete container
$app->get('/delete/{container}/{object}', function ($container, $object) use ($app) {
  $container = urldecode($container);
  $object = urldecode($object);
  if (empty($object)) {
    $objects = json_decode($app['os']->listObjects($container));
    foreach ($objects as $o) {
      $app['os']->deleteObject($container, $o->name);  
    }
    $app['os']->deleteContainer($container);    
  } else {
    $app['os']->deleteObject($container, $object);  
  }
  return $app->redirect($app["url_generator"]->generate('index'));
})
->value('object', '')
->before($authenticate);

// login handler
// check if authenticated against provider
// retrieve user email address and save to session
$app->get('/login', function () use ($app, $auth) {
  $google = $auth->authenticate("Google");
  $currentUser = $google->getUserProfile();
  $_SESSION['uid'] = $currentUser->email;
  return $app->redirect($app["url_generator"]->generate('index'));
})
->bind('login');

// logout handler
// log out and display logout information page
$app->get('/logout', function () use ($app, $auth) {
  $auth->logoutAllProviders();
  session_destroy();
  return $app['twig']->render('logout.twig');
})
->before($authenticate);

// OAuth callback handler
$app->get('/callback', function () {
  return Hybrid_Endpoint::process();
});

// legal page
$app->get('/legal', function () use ($app) {
  return $app['twig']->render('legal.twig');
});

// delete-my-data handler
$app->get('/delete-my-data', function () use ($app) {
  $containers = (array) $app['os']->listContainers();
  foreach ($containers as &$c) {
    $objects = json_decode($app['os']->listObjects($c['name']));
    foreach ($objects as &$o) {
      $app['os']->deleteObject($c['name'], $o->name);  
    }
    $app['os']->deleteContainer($c['name']);    
  }
  return $app->redirect($app["url_generator"]->generate('index'));
})
->before($authenticate);

$app->error(function (\Exception $e, $code) use ($app) {
  return $app['twig']->render('error.twig', array('error' => $e->getMessage()));
});

$app->run();
