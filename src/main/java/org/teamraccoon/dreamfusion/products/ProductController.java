package org.teamraccoon.dreamfusion.products;

import java.util.List;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.teamraccoon.dreamfusion.generic.IGenericFullService;
import org.teamraccoon.dreamfusion.generic.IGenericSearchService;
import org.teamraccoon.dreamfusion.messages.Message;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping(path = "${api-endpoint}/products")
public class ProductController {

    IGenericFullService<Product, ProductDTO> service;
    IGenericSearchService<Product> searchService;

    @GetMapping(path = "")
    public List<Product> index() {

        List<Product> products = service.getAll();

        return products;
    }

    @GetMapping(path = "/{id}")
    public ResponseEntity<Product> findById(@PathVariable("id") @NonNull Long id) throws Exception {

        Product product = service.getById(id);

        return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(product);
    }

    @GetMapping(path = "getByName/{name}")
    public ResponseEntity<Product> findByName(@PathVariable("name") @NonNull String name) throws Exception {

        Product product = service.getByName(name);

        return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(product);
    }

    @GetMapping(path = "getManyByName/{name}")
    public ResponseEntity<List<Product>> findManyByName(@PathVariable("name") @NonNull String name) throws Exception {

        List<Product> products = searchService.getManyByName(name);

        return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(products);
    }

    @GetMapping(path = "getManyByCategoryName/{name}")
    public ResponseEntity<List<Product>> findManyByCategoryName(@PathVariable("name") @NonNull String name) throws Exception {

        List<Product> products = searchService.getManyByCategoryName(name);

        return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(products);
    }

    @PostMapping(path = "")
    public ResponseEntity<Product> create(@RequestBody ProductDTO product) {

        Product newProduct = service.save(product);

        return ResponseEntity.status(201).body(newProduct);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Product> update(@PathVariable("id") @NonNull Long id, @RequestBody ProductDTO product) throws Exception {

        Product updatedProduct = service.update(id, product);

        return ResponseEntity.status(200).body(updatedProduct);
    }

    @DeleteMapping(path = "/{id}")
    public ResponseEntity<Message> remove(@PathVariable("id") @NonNull Long id) throws Exception { 

        Message delete = service.delete(id);

        return ResponseEntity.status(200).body(delete);
    }

}