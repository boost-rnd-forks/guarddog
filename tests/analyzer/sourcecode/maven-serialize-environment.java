// ruleid: maven-serialize-environment
new ObjectMapper().writeValueAsString(System.getenv());

// ruleid: maven-serialize-environment
new Gson().toJson(System.getenv());

// ruleid: maven-serialize-environment
System.getenv().toString();

// ruleid: maven-serialize-environment
String.valueOf(System.getenv());

// ruleid: maven-serialize-environment
String envData = System.getenv().toString();

// ruleid: maven-serialize-environment
String jsonEnv = new ObjectMapper().writeValueAsString(System.getenv());

// ruleid: maven-serialize-environment
String gsonEnv = new Gson().toJson(System.getenv());

// ok: maven-serialize-environment
System.getenv("PATH");

// ok: maven-serialize-environment
System.getenv("HOME");

// ok: maven-serialize-environment
Map<String, String> envMap = System.getenv(); 