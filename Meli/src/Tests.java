
import static org.junit.Assert.*;

import java.util.LinkedList;
import java.util.List;

import org.junit.Test;

public class Tests {

	String TEST_URL = "https://xss-game.appspot.com/level1/frame";
	Form TEST_FORM;
	List<Form> TEST_FORMS_LIST = new LinkedList<Form>();
	
	@Test
	public void testAttackOnVuln() {
		App app = new App();
		TEST_FORM = new Form("GET");
		TEST_FORM.addInput("query");
		TEST_FORMS_LIST.add(TEST_FORM);
		boolean vuln_found = app.attack(TEST_URL, TEST_FORMS_LIST);
		assertTrue(vuln_found);
	}
	
	@Test
	public void testAttackNotOnVuln() {
		App app = new App();
		TEST_FORM = new Form("POST");
		TEST_FORM.addInput("q");
		TEST_FORMS_LIST.add(TEST_FORM);
		boolean vuln_found = app.attack(TEST_URL, TEST_FORMS_LIST);
		assertTrue(vuln_found);
	}

}
