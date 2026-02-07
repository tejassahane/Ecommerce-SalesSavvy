package com.kodnest.app.userserviceimplementations;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kodnest.app.entities.Cart_Items;
import com.kodnest.app.entities.Product;
import com.kodnest.app.entities.ProductImage;
import com.kodnest.app.entities.User;
import com.kodnest.app.userrepositories.CartRepository;
import com.kodnest.app.userrepositories.ProductImageRepository;
import com.kodnest.app.userrepositories.ProductRepository;
import com.kodnest.app.userrepositories.UserRepository;
import com.kodnest.app.userservices.CartServiceContract;

@Service
public class CartService implements CartServiceContract {
	
	ProductRepository productRepository;
	CartRepository cartRepository;
	ProductImageRepository productImageRepository;
	UserRepository userRepository;
	
	

public CartService(ProductRepository productRepository, CartRepository cartRepository,
			ProductImageRepository productImageRepository, UserRepository userRepository) {
		super();
		this.productRepository = productRepository;
		this.cartRepository = cartRepository;
		this.productImageRepository = productImageRepository;
		this.userRepository = userRepository;
	}

//	public CartService(ProductRepository producrRepository, CartRepository cartRepository, ProductRepository productRepository) {
//		super();
//		this.productRepository = productRepository;
//		this.cartRepository = cartRepository;
//	}

public void addToCart(User user, int productId, int quantity) {
		
		Product product = productRepository.findById(productId)
				.orElseThrow(() -> new IllegalArgumentException("Product not found with ID: " + productId));

		// Fetch cart item for this userId and productId
		Optional<Cart_Items> existingItem = cartRepository.findByUserAndProduct(user.getUserId(), productId);

		if (existingItem.isPresent()) {
			Cart_Items cartItem = existingItem.get();
			cartItem.setQuantity(cartItem.getQuantity() + quantity);
			cartRepository.save(cartItem);
		} else {
			Cart_Items newItem = new Cart_Items(user, product, quantity);
			cartRepository.save(newItem);
		}
	}

@Override
public Map<String, Object> getCartItems(User authenticatedUser) {
	List<Cart_Items> cartItems = cartRepository.findCartItemsWithProductDetails(authenticatedUser.getUserId());
	Map<String, Object> response = new HashMap();
	response.put("username", authenticatedUser.getUsername());
	response.put("role", authenticatedUser.getRole().toString());
	
	List<Map<String, Object>> products = new ArrayList<>();
	int overallTotalPrice = 0;
	
	for (Cart_Items cartItem : cartItems) {
		Map<String, Object> productDetails = new HashMap<>();
		Product product = cartItem.getProduct();

		List<ProductImage> productImages = productImageRepository.findByProduct_ProductId(product.getProductId());
		
		
//		String imageurl;
//		if (productImages != null && !productImages.isEmpty()) {
//			// If there are images, get the first image's URL
//			imageurl = productImages.get(0).getImageUrl();
//		} else {
//			// Set a default image if no images are available
//			imageurl = "default-image-url";  // You can replace this with your default image URL
//		}
//		
		  String imageurl = (productImages != null && !productImages.isEmpty())
                  ? productImages.get(0).getImageUrl()
                  : "default-image-url";
		
		productDetails.put("product_id", product.getProductId());
		productDetails.put("image_url", imageurl);
		productDetails.put("name", product.getName());
		productDetails.put("description", product.getDescription());
		productDetails.put("price_per_unit", product.getPrice());
		productDetails.put("quantity", cartItem.getQuantity());
		productDetails.put("total_price", cartItem.getQuantity() * product.getPrice().doubleValue());
		
		// Add the product details to the products list
					products.add(productDetails);

					// Add to the overall total price
					overallTotalPrice += cartItem.getQuantity() * product.getPrice().doubleValue();
		
	}
					// Prepare the final cart response
					Map<String, Object> cart = new HashMap<>();
					cart.put("products", products);
					cart.put("overall_total_price", overallTotalPrice);

					// Add the cart details to the response
					response.put("cart", cart);

					return response;
					
	
}

@Override
// Update Cart Item Quantity
public void updateCartItemQuantity(User authenticatedUser, int productId, int quantity) {
			User ref = userRepository.findById(authenticatedUser.getUserId()).orElseThrow(() -> new IllegalArgumentException("User not found"));

			Product product = productRepository.findById(productId)
					.orElseThrow(() -> new IllegalArgumentException("Product not found"));

			// Fetch cart item for this userId and productId
			Optional<Cart_Items> existingItem = cartRepository.findByUserAndProduct(authenticatedUser.getUserId(), productId);

			if (existingItem.isPresent()) {
				Cart_Items cartItem = existingItem.get();
				if (quantity == 0) {
					deleteCartItem(authenticatedUser.getUserId(), productId);
				} else {
					cartItem.setQuantity(quantity);
					cartRepository.save(cartItem);
				}
			}
			else {
				throw new RuntimeException("Cart Item not Found associated with product and user");
			}
		}


//Delete Cart Item
	public void deleteCartItem(int userId, int productId) {
//		User user = userRepository.findById(userId)
//		.orElseThrow(() -> new IllegalArgumentException("User not found"));

	Product product = productRepository.findById(productId)
				.orElseThrow(() -> new IllegalArgumentException("Product not found"));

	cartRepository.deleteCartItem(userId, productId);
	}

	
	@Override
	public int getCartItemCount(int userId) {
		int count = cartRepository.countTotalItems(userId);
		return count;
	}

}


