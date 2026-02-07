package com.kodnest.app.userservices;

import java.util.Map;

import com.kodnest.app.entities.User;

public interface OrderServiceContract {
	public Map<String, Object> getOrdersForUser(User user);

}