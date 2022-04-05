package com.example.vulnspring;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Controller
public class WebController {

	@Autowired
	JdbcTemplate jdbcTemplate;

	private static final Logger logger = LoggerFactory.getLogger(WebController.class);

	@GetMapping(value = { "/", "/home" })
	public String home(Model model, HttpSession session) {
		model.addAttribute("username", session.getAttribute("username"));
		return "home";
	}

	@GetMapping("/login")
	public String login(Model model) {
		return "login";
	}

	@PostMapping("/login")
	public String login(HttpSession session, @RequestParam(name = "username", required = true) String username,
			@RequestParam(name = "password", required = true) String password, Model model) {
		if (loginSuccess(username, password)) {
			logger.debug("Login with: " + username + ":" + password); // Issue - password logged
			session.setAttribute("username", username);
			return "redirect:home";
		}
		logger.debug("Failed login for " + username);
		return "login";
	}

	private boolean loginSuccess(String username, String password) {
		if (username == null || password == null)
			return false;
		// Issue - SQL Injection
		try {
			String query = "SELECT * FROM users WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\"";
			Map<String, Object> result = jdbcTemplate.queryForMap(query);
			if (result.containsKey("username"))
				return true;
			else
				return false;
		} catch (EmptyResultDataAccessException e) {
			return false;
		}
	}

	@GetMapping("/logout")
	public String logout(HttpSession session) {
		session.invalidate();
		return "redirect:home";
	}

	@GetMapping("/update")
	public String update(HttpSession session, Model model) {
		String statement = "SELECT name FROM users WHERE username=?";
		Map<String, Object> resultMap = jdbcTemplate.queryForMap(statement,
				new Object[] { session.getAttribute("username") });

		// Stored XSS
		model.addAttribute("name", resultMap.get("name"));
		return "update";
	}

	@PostMapping("/update")
	public String update(HttpSession session, @RequestParam(name = "newname") String newName, Model model) {
		String statement = "UPDATE users SET name = ? WHERE username = ?";
		int status = jdbcTemplate.update(statement, new Object[] { newName, session.getAttribute("username") });
		logger.info("Running statement: " + statement + newName + " " + session.getAttribute("username"));
		logger.info("Result status for transfer is " + String.valueOf(status));

		if (status == 1) {
			model.addAttribute("error", "Update Failed!");
			// Reflected XSS
			model.addAttribute("name", newName);
		}
		return "update";
	}

	@PostMapping("/checkdb")
	public String checkDB(@RequestParam(name = "dbpath") String dbpath, Model model)
			throws MalformedURLException, IOException {
		// Issue - SSRF
		String out = new Scanner(new URL(dbpath).openStream(), "UTF-8").useDelimiter("\\A").next();
		model.addAttribute("dbResponse", out);
		return "checkdb";
	}

	@GetMapping("/checkdb")
	public String checkDB() {
		return "checkdb";
	}

	@GetMapping("/transfer")
	public String transfer(HttpSession session, Model model) {
		String getBalanceStatement = "SELECT * FROM users WHERE username=?";
		Map<String, Object> balanceResultMap = jdbcTemplate.queryForMap(getBalanceStatement,
				new Object[] { session.getAttribute("username") });

		float balance = (float) balanceResultMap.get("balance");
		model.addAttribute("balance", balance);
		return "transfer";
	}

	// Issue - CSRF
	@Transactional
	@PostMapping("/transfer")
	public String transfer(HttpSession session, @RequestParam(name = "toaccount") String toAccount,
			@RequestParam(name = "amount") Float amount, Model model) {

		String fromAccount;
		Float fromAccountBalance;
		Float toAccountBalance;

		// Sanity check for transaction
		if (amount < 0) {
			model.addAttribute("error", "Negative amount value!");
			logger.info("negative amount value");
			return "transfer";
		}

		// Validate To Account
		String toAccountValidatestatement = "SELECT * FROM users WHERE accountnumber=?";
		try {
			Map<String, Object> toAccountResultMap = jdbcTemplate.queryForMap(toAccountValidatestatement,
					new Object[] { toAccount });
			toAccountBalance = (Float) toAccountResultMap.get("balance");
		} catch (EmptyResultDataAccessException e) {
			model.addAttribute("error", "Invalid To Account");
			logger.info("Invalid To Account");
			return "transfer";
		}

		// Ensure sufficient balance is available
		String fromAccountStatement = "SELECT * FROM users WHERE username=?";
		Map<String, Object> fromResultMap = jdbcTemplate.queryForMap(fromAccountStatement,
				new Object[] { session.getAttribute("username") });

		fromAccountBalance = (float) fromResultMap.get("balance");
		fromAccount = (String) fromResultMap.get("accountnumber");
		logger.info("got balance = " + String.valueOf(fromAccountBalance));

		float newBalance = fromAccountBalance - amount;
		if (newBalance < 0) {
			model.addAttribute("error", "not enough balance");
			logger.info("Not enought balance");
			return "transfer";
		}

		// Perform transaction
		String toAccStatement = "UPDATE users SET balance = ? WHERE accountnumber = ?";
		int toAccStatus = jdbcTemplate.update(toAccStatement, new Object[] { toAccountBalance + amount, toAccount });
		logger.info(
				"Running statement: " + toAccStatement + String.valueOf(toAccountBalance + amount) + " " + toAccount);
		logger.info("Result status for transfer is " + String.valueOf(toAccStatus));

		String fromAccStatement = "UPDATE users SET balance = ? WHERE accountnumber = ?";
		int fromAccStatus = jdbcTemplate.update(toAccStatement,
				new Object[] { fromAccountBalance - amount, fromAccount });
		logger.info("Running statement: " + fromAccStatement + String.valueOf(fromAccountBalance - amount) + " "
				+ fromAccount);
		logger.info("Result status for transfer is " + String.valueOf(fromAccStatus));

		if (toAccStatus == 1 && fromAccStatus == 1) {
			model.addAttribute("balance", newBalance);
			model.addAttribute("message", "Balance Transfer Successful!");
		} else {
			model.addAttribute("error", "Balance Transfer Failed!");
		}

		return "transfer";

	}

	@GetMapping("/issue")
	public String issue(Model model) {
		return "issue";
	}

	@PostMapping(value = "/issue", consumes = MediaType.APPLICATION_XML_VALUE)
	public String issue(Model model, @RequestBody String body)
			throws ParserConfigurationException, SAXException, IOException {
		// Issue - XXE
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(new InputSource(new StringReader(body)));

		String parsedDocument = getNodeString(doc.getFirstChild(), new StringBuffer()).toString();
		logger.debug("Parsed XML: \n" + parsedDocument);
		model.addAttribute("parsedDocument", parsedDocument);

		return "issue";
	}

	StringBuffer getNodeString(Node node, StringBuffer currentString) {
		String nodeName = node.getNodeName();
		// ignore empty text node
		if (nodeName.equals("#text") && node.getNodeValue().trim().equals("")) {
			return currentString;
		}
		currentString.append("<" + nodeName + ">");
		if (node.getNodeValue() != null) {
			currentString.append(node.getNodeValue());
		}
		for (int i = 0; i < node.getChildNodes().getLength(); i++) {
			currentString = getNodeString(node.getChildNodes().item(i), currentString);
		}
		currentString.append("</" + nodeName + ">");
		return currentString;
	}

	@GetMapping("/support")
	public String support(@RequestParam(required = false) String desk) {
		String helpDeskLocation = desk;
		if (helpDeskLocation != null)
			// Issue - Open Redirect
			return "redirect:" + helpDeskLocation;
		return "support";
	}

	@GetMapping("/support/*")
	public String support(Model model) {
		model.addAttribute("supportmessage",
				"Support Desk is under construction. Send an email to support@example.com.");
		return "support";
	}

	@GetMapping("/token")
	public String jwt(HttpSession session, Model model) {
		String username = (String) session.getAttribute("username");

		// Issue - JWT - Insecure Implementation
		Algorithm algorithmNone = Algorithm.none();
		String token = JWT.create().withIssuer("vulnspring").withClaim("username", username).sign(algorithmNone);
		logger.debug("Generated Token: " + token);
		model.addAttribute("generatedtoken", token);
		return "token";
	}

	@PostMapping("/token")
	public String jwt(Model model, @RequestParam String jwtString, HttpSession session) {
		DecodedJWT decodedJWT = JWT.decode(jwtString);

		// Logical Flow - No validation, just decoding
		String usernameFromJWT = decodedJWT.getClaim("username").asString();
		if (usernameFromJWT.equalsIgnoreCase((String) session.getAttribute("username"))) {
			model.addAttribute("isValidMessage", "Token is valid for your username!");
		} else {
			model.addAttribute("isValidMessage", "Invalid Token!");
		}
		return "token";
	}

	@GetMapping("/address")
	public String addressValidation(Model model) throws IOException {
		AddressDetails ad = new AddressDetails(1, "Bourke Street");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(ad);
		oos.close();
		String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());
		model.addAttribute("encodedAddress", b64);
		return "address";
	}

	@PostMapping("/address")
	public String addressValidation(Model model, @RequestParam String encodedString) {
		byte[] data = Base64.getDecoder().decode(encodedString);
		ObjectInputStream ois;
		try {
			// Issue - Insecure Deserialization
			ois = new ObjectInputStream(new ByteArrayInputStream(data));
			AddressDetails addressDetails = (AddressDetails) ois.readObject();
			ois.close();
			model.addAttribute("decodedAddress", addressDetails);
		} catch (IOException e) {
			e.printStackTrace();
			model.addAttribute("decodedAddress", "Error: Something went wrong with deserialization!");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			model.addAttribute("decodedAddress", "Error: Something went wrong with deserialization!");
		}
		return "address";
	}

}

class AddressDetails implements Serializable {
	int streetNumber;

	public int getStreetNumber() {
		return streetNumber;
	}

	public String getStreetName() {
		return streetName;
	}

	String streetName;

	AddressDetails(int streetNumber, String streetName) {
		this.streetNumber = streetNumber;
		this.streetName = streetName;
	}

	@Override
	public String toString() {
		return "{streetNumber: " + streetNumber + ", streetName: " + streetName + "}";
	}

}