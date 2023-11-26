package com.hit.community.controller;

import com.hit.community.dto.BoardDTO;
import com.hit.community.service.BoardService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/boards")
@RequiredArgsConstructor
public class RestBoardController {

    private final BoardService boardService;

    // Create a new board
    @PostMapping
    public ResponseEntity<BoardDTO> createBoard(@RequestBody BoardDTO boardDTO) {
        boardService.save(boardDTO);
        return ResponseEntity.ok(boardDTO);
    }

//    // Get all boards
//    @GetMapping
//    public ResponseEntity<List<BoardDTO>> getAllBoards() {
//        List<BoardDTO> boardDTOList = boardService.findAll();
//        return ResponseEntity.ok(boardDTOList);
//    }

    // Get a single board by ID
    @GetMapping("/{id}")
    public ResponseEntity<BoardDTO> getBoardById(@PathVariable Long id) {
        boardService.updateHits(id);
        BoardDTO boardDTO = boardService.findById(id);
        return boardDTO != null ? ResponseEntity.ok(boardDTO) : ResponseEntity.notFound().build();
    }

    // Update a board
    @PutMapping("/{id}")
    public ResponseEntity<BoardDTO> updateBoard(@PathVariable Long id, @RequestBody BoardDTO boardDTO) {
        BoardDTO existingBoard = boardService.findById(id);
        if (existingBoard == null) {
            return ResponseEntity.notFound().build();
        }
        int hits = existingBoard.getBoardHits();
        boardDTO.setId(id); boardDTO.setBoardHits(hits);
        BoardDTO updatedBoard = boardService.update(boardDTO);
        return ResponseEntity.ok(updatedBoard);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteBoard(@PathVariable Long id) {
        boardService.delete(id);
        return ResponseEntity.ok().build();
    }


    // GET /boards?page=0&size=10
    @GetMapping
    public ResponseEntity<Page<BoardDTO>> getAllBoards(Pageable pageable) {
        Page<BoardDTO> boardPage = boardService.findAllPaged(pageable);
        return ResponseEntity.ok(boardPage);
    }


}
