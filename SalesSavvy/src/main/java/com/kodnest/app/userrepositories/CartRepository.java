package com.kodnest.app.userrepositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.kodnest.app.entities.Cart_Items;

import jakarta.transaction.Transactional;

@Repository
public interface CartRepository extends JpaRepository<Cart_Items, Integer>{
	 @Query("SELECT c FROM Cart_Items c WHERE c.user.userId = :userId AND c.product.productId = :productId")
	    Optional<Cart_Items> findByUserAndProduct(int userId, int productId);
	    
	    
	    @Query("SELECT c FROM Cart_Items c JOIN FETCH c.product p LEFT JOIN FETCH ProductImage pi ON p.productId = pi.product.productId WHERE c.user.userId = :userId")
	    List<Cart_Items> findCartItemsWithProductDetails(int userId);
	    
	    
	   // update quantity for a specific cart item
	    @Query("UPDATE Cart_Items c SET c.quantity = :quantity WHERE c.id = :cartItemId")
	    void updateCartItemQuantity(int cartItemId, int quantity);

	    
	    @Modifying
	    @Transactional
	    @Query("DELETE FROM Cart_Items c WHERE c.user.userId = :userId AND c.product.productId = :productId")
	    void deleteCartItem(int userId, int productId);
	    
	    // Count the total quantity of items in the cart
	    @Query("SELECT COALESCE(SUM(c.quantity), 0) FROM Cart_Items c WHERE c.user.userId = :userId")
	    int countTotalItems(int userId);
	    
	    @Modifying
	    @Transactional
	    @Query("DELETE FROM Cart_Items c WHERE c.user.userId = :userId")
	    void deleteAllCartItemsByUserId(int userId);
}
