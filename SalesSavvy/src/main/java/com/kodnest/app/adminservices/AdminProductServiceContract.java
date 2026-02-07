package com.kodnest.app.adminservices;

import com.kodnest.app.entities.Product;

public interface AdminProductServiceContract {
	 public Product addProductWithImage(String name, String description, Double price, Integer stock, Integer categoryId, String imageUrl);
	 public void deleteProduct(Integer productId);
}
