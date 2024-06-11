import React, { Component } from 'react';
import Cookie from "js-cookie"
import "./index.css"

class Home extends Component {
    constructor(props) {
        super(props);

        this.state = {
            items: [
                { id: 1, name: 'Item 1', category: 'Category A', date: '2024-06-01' },
                { id: 2, name: 'Item 2', category: 'Category B', date: '2024-06-02' },
                { id: 3, name: 'Item 3', category: 'Category A', date: '2024-06-03' },
            ],
            newItem: {
                id: null,
                name: '',
                category: '',
                date: ''
            },
            filterName: '',
            filterCategory: '',
            sortField: '',
            sortOrder: 'asc'
        };
    }

    handleLogout = () => {
        Cookie.remove('jw_token') 
        this.props.history.push('/signin');
    };

    handleInputChange = (event) => {
        const { name, value } = event.target;
        this.setState({
            newItem: {
                ...this.state.newItem,
                [name]: value
            }
        });
    };

    handleAddItem = () => {
        const { items, newItem } = this.state;
        newItem.id = Date.now(); 
        const updatedItems = [...items, newItem];
        this.setState({
            items: updatedItems,
            newItem: {
                id: null,
                name: '',
                category: '',
                date: ''
            }
        });
    };

    handleUpdateItem = (id, updatedItem) => {
        const updatedItems = this.state.items.map(item =>
            item.id === id ? { ...item, ...updatedItem } : item
        );
        this.setState({ items: updatedItems });
    };

    handleDeleteItem = (id) => {
        const updatedItems = this.state.items.filter(item => item.id !== id);
        this.setState({ items: updatedItems });
    };

    handleFilterByName = (event) => {
        this.setState({ filterName: event.target.value });
    };

    handleFilterByCategory = (event) => {
        this.setState({ filterCategory: event.target.value });
    };

    handleSort = (field) => {
        const { items, sortOrder } = this.state;
        let sortedItems = [...items];
        sortedItems.sort((a, b) => {
            if (sortOrder === 'asc') {
                return a[field] > b[field] ? 1 : -1;
            } else {
                return a[field] < b[field] ? 1 : -1;
            }
        });
        this.setState({
            items: sortedItems,
            sortField: field,
            sortOrder: sortOrder === 'asc' ? 'desc' : 'asc'
        });
    };

    render() {
        const { items, newItem, filterName, filterCategory, sortField, sortOrder } = this.state;

        let filteredItems = items.filter(item =>
            item.name.toLowerCase().includes(filterName.toLowerCase()) &&
            item.category.toLowerCase().includes(filterCategory.toLowerCase())
        );

        if (sortField) {
            filteredItems.sort((a, b) => {
                if (sortOrder === 'asc') {
                    return a[sortField] > b[sortField] ? 1 : -1;
                } else {
                    return a[sortField] < b[sortField] ? 1 : -1;
                }
            });
        }

        return (
            <div>
                <div className="top-bar">
                    <h1>Bindassdeal</h1>
                    <button className="btn" onClick={this.handleLogout}>Logout</button>
                </div>
                <div className="content">
                    <h2>Items</h2>
                    <div className="filters">
                        <input
                            type="text"
                            placeholder="Search by name"
                            value={filterName}
                            onChange={this.handleFilterByName}
                        />
                        <input
                            type="text"
                            placeholder="Filter by category"
                            value={filterCategory}
                            onChange={this.handleFilterByCategory}
                        />
                        <button className="btn" onClick={() => this.handleSort('name')}>
                            Sort by Name {sortField === 'name' && sortOrder === 'asc' && '▲'}
                            {sortField === 'name' && sortOrder === 'desc' && '▼'}
                        </button>
                        <button className="btn" onClick={() => this.handleSort('date')}>
                            Sort by Date {sortField === 'date' && sortOrder === 'asc' && '▲'}
                            {sortField === 'date' && sortOrder === 'desc' && '▼'}
                        </button>
                    </div>
                    <ul>
                        {filteredItems.map(item => (
                            <li key={item.id}>
                                {item.name} - {item.category} - {item.date}
                                <button className="btn" onClick={() => this.handleDeleteItem(item.id)}>Delete</button>
                                <button className="btn" onClick={() => this.handleUpdateItem(item.id, { name: 'Updated Item' })}>Update</button>
                            </li>
                        ))}
                    </ul>
                    <div className="form">
                        <h3>Add New Item</h3>
                        <input
                            type="text"
                            name="name"
                            placeholder="Name"
                            value={newItem.name}
                            onChange={this.handleInputChange}
                        />
                        <input
                            type="text"
                            name="category"
                            placeholder="Category"
                            value={newItem.category}
                            onChange={this.handleInputChange}
                        />
                        <input
                            type="text"
                            name="date"
                            placeholder="Date"
                            value={newItem.date}
                            onChange={this.handleInputChange}
                        />
                        <button className="btn" onClick={this.handleAddItem}>Add Item</button>
                    </div>
                </div>
            </div>
        );
    }
}

export default Home;
