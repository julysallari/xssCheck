import java.util.LinkedList;
import java.util.List;

public class Form {

	List<String> inputs = new LinkedList<String>();
	String type;
	
	public Form(String type){
		this.type = type;
	}
	
	public void addInput(String input){
		this.inputs.add(input);
	}
	
	public List<String> getInputs(){
		return this.inputs;
	}
	
	public String getType(){
		return this.type;
	}
}
