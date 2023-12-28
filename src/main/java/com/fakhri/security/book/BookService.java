package com.fakhri.security.book;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class BookService {

    private final BookRepository bookRepository ;

    public List<Book> findAll() {
        return bookRepository.findAll();
    }

    public void save(BookRequest request){
        var book = Book.builder()
                .id(request.getId())
                .author(request.getAuthor())
                .isbn(request.getIsbn())
                .build() ;
        bookRepository.save(book) ;
    }
}
