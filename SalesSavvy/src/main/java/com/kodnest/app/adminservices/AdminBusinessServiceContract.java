package com.kodnest.app.adminservices;

import java.time.LocalDate;
import java.util.Map;

public interface AdminBusinessServiceContract {

	public Map<String, Object> calculateMonthlyBusiness(int month, int year);
	public Map<String, Object> calculateDailyBusiness(LocalDate date);
	public Map<String, Object> calculateYearlyBusiness(int year);
	public Map<String, Object> calculateOverallBusiness();
}
