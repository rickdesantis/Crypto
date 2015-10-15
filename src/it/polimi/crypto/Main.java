package it.polimi.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

public class Main {
	
	private static final Logger logger = LoggerFactory.getLogger(Main.class);
	
	@Parameter(names = "-chars", description = "Number of chars")
	private int chars = Crypter.DEFAULT_CHARS;
	
	@Parameter(names = "-tests", description = "Number of tests")
	private int tests = 5;
	
	@Parameter(names = "-testsAverage", description = "Number of tests to consider for the average")
	private int testsAverage = 100;
	
	@Parameter(names = "-sleepMin", description = "Milliseconds to wait between each test (min)")
	private int sleepBetweenMin = 1000;
	
	@Parameter(names = "-sleepMax", description = "Milliseconds to wait between each test (max)")
	private int sleepBetweenMax = 3000;
	
	@Parameter(names = "-sleepLong", description = "Milliseconds to wait when there is a problem")
	private int sleepBetweenLong = 5*60*1000;
	
	@Parameter(names = "-sleepTestsMin", description = "Number of tests after which we'll wait (min)")
	private int sleepTestsMin = 20;
	
	@Parameter(names = "-sleepTestsMax", description = "Number of tests after which we'll wait (max)")
	private int sleepTestsMax = 50;
	
	@Parameter(names = "-out", description = "The path to the file where the output will be written")
	private String fileName = null;
	
	@Parameter(names = "-duration", description = "The total duration of the test in seconds (ovverrides the -tests parameter)")
	private int duration = -1;
	
	@Parameter(names = { "-h", "--help" }, help = true)
	private boolean help;


	public static void main(String[] args) {
		Main m = new Main();
		JCommander jc = new JCommander(m, args);
		
		if (m.help) {
			jc.usage();
			System.exit(0);
		}
		
		PrintStream out = null;
		if (m.fileName == null || new File(m.fileName).isDirectory())
			out = System.out;
		else {
			File f = new File(m.fileName);
			try {
				out = new PrintStream(f);
			} catch (FileNotFoundException e) {
				out = System.out;
			}
		}
		
		try {
			List<Long> res;
			if (m.duration > 0)
				res = Crypter.doTestsForDuration(m.chars, m.duration, m.sleepBetweenMin, m.sleepBetweenMax, m.sleepTestsMin, m.sleepTestsMax, m.sleepBetweenLong, m.testsAverage, out);
			else
				res = Crypter.doTests(m.chars, m.tests, m.sleepBetweenMin, m.sleepBetweenMax, m.sleepTestsMin, m.sleepTestsMax, m.sleepBetweenLong, m.testsAverage, out);
			
			
			if (res.size() > 0) {
				long min = res.get(0);
				long max = res.get(0);
				double sum = 0.0;
				for (long l : res) {
					if (l < min)
						min = l;
					if (l > max)
						max = l;
					sum += l;
				}
				double avg = sum/res.size();
				
				out.printf("\nMin: %d, Max: %d, Avg: %f\n", min, max, avg);
			}
		} catch (Exception e) {
			logger.error("Error while performing the tests.", e);
		}
		
		if (out != System.out) {
			out.flush();
			out.close();
		}
	}

}
