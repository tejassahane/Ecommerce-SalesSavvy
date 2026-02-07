package com.kodnest.app.userservices;

import java.util.Map;

import com.kodnest.app.entities.User;

public interface CartServiceContract {
public void addToCart(User user, int productId, int quantity);
public Map<String, Object> getCartItems(User authenticatedUser);

public void updateCartItemQuantity(User authenticatedUser, int productId, int quantity);
public void deleteCartItem(int userId, int productId);

public int getCartItemCount(int userId);
}
