package com.kodnest.app.adminservices;

import com.kodnest.app.entities.User;

public interface AdminUserServiceContract {
	 public User modifyUser(Integer userId, String username, String email, String role);

	 public User getUserById(Integer userId);

}
